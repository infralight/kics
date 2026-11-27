// kics-serve: a long-lived KICS process. Stock queries are compiled once at start (engine.WarmShared);
// each job is a normal KICS scan (pkg/scan, same code path and JSON report as `kics scan`) run in-process.
//
//	kics-serve -socket /tmp/kics.sock -queries-path /queries/terraform
//
// It listens on a unix socket only, readable and writable by its own user: a job is trusted like the
// arguments of `kics scan`, so only a local caller that could run the CLI itself can send one.
//
// POST /scan  body: JSON with `kics scan` flag names, e.g.
//
//	{"path":["/work/plan.json"],"queries-path":["/work/rules","/queries/terraform"],
//	 "output-path":"/work","output-name":"results","report-formats":["json"],"type":["Terraform"]}
//
// path and output-path are required; other fields left out take the `kics scan` defaults, and queries-path
// defaults to the stock queries. reply: {"durationSec":..,"error":""}; the report is written to
// <output-path>/<output-name>.json as by the CLI.
// GET /healthz -> 200 once warm; GET /stats -> heap and cache counters.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Checkmarx/kics/v2/pkg/engine"
	"github.com/Checkmarx/kics/v2/pkg/engine/source"
	consolePrinter "github.com/Checkmarx/kics/v2/pkg/printer"
	"github.com/Checkmarx/kics/v2/pkg/progress"
	"github.com/Checkmarx/kics/v2/pkg/scan"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type job struct {
	Path               []string `json:"path"`
	QueriesPath        []string `json:"queries-path"`
	OutputPath         string   `json:"output-path"`
	OutputName         string   `json:"output-name"`
	ReportFormats      []string `json:"report-formats"`
	Type               []string `json:"type"`
	MaxFileSize        int      `json:"max-file-size"`
	SecretsRegexesPath string   `json:"secrets-regexes-path"`
	Timeout            int      `json:"timeout"`
	ExcludeQueries     []string `json:"exclude-queries"`
	CloudProvider      []string `json:"cloud-provider"`
}

// prepare rejects a job that cannot produce a report and gives the fields it leaves out the `kics scan`
// defaults; queries default to the stock queries the process was started with.
func (j *job) prepare(stock string) error {
	if len(j.Path) == 0 {
		return errors.New("path is required")
	}
	if j.OutputPath == "" {
		return errors.New("output-path is required")
	}
	if len(j.QueriesPath) == 0 {
		j.QueriesPath = []string{stock}
	}
	if j.OutputName == "" {
		j.OutputName = "results"
	}
	j.OutputName = filepath.Base(j.OutputName) // as the CLI: a file name inside output-path
	if j.MaxFileSize == 0 {
		j.MaxFileSize = 5 // MB; 0 would skip every non-empty file
	}
	if j.Timeout == 0 {
		j.Timeout = 60 // seconds; 0 would cancel the scan at once
	}
	if len(j.CloudProvider) == 0 {
		j.CloudProvider = []string{""}
	}
	if len(j.Type) == 0 {
		j.Type = []string{""} // all platforms; the analyzer reads the first element
	}
	return nil
}

func main() {
	socket := flag.String("socket", "/tmp/kics.sock", "unix socket to listen on")
	stock := flag.String("queries-path", "./assets/queries/terraform", "stock queries compiled at start")
	maxConc := flag.Int("max-concurrent", 8, "scans running at once")
	customCache := flag.Int("custom-query-cache", engine.DefaultCustomQueryCacheSize, "compiled custom queries kept")
	logLevel := flag.String("log-level", "error", "zerolog level; debug prints per-query durations")
	sharedCompiler := flag.Bool("shared-compiler", true, "compile stock queries once at start; false = compile per scan like the CLI")
	flag.Parse()
	if *maxConc < 1 {
		fatal(errors.New("-max-concurrent must be at least 1"))
	}
	lvl, err := zerolog.ParseLevel(*logLevel)
	fatal(err)
	zerolog.SetGlobalLevel(lvl)

	t := time.Now()
	src := source.NewFilesystemSource([]string{*stock}, []string{"terraform"}, []string{""}, source.LibrariesDefaultBasePath, false)
	queries, err := src.GetQueries(&source.QueryInspectorParameters{})
	fatal(err)
	common, err := src.GetQueryLibrary("common")
	fatal(err)
	platform, err := src.GetQueryLibrary("terraform")
	fatal(err)
	n := 0
	if *sharedCompiler {
		n, err = engine.WarmShared(queries, common, platform, *customCache)
		fatal(err) // self-check failed: refuse to serve with fewer queries
	}
	fmt.Fprintf(os.Stderr, `{"msg":"warm","queries":%d,"sec":%.3f,"gomaxprocs":%d}`+"\n", n, time.Since(t).Seconds(), runtime.GOMAXPROCS(0))

	sem := make(chan struct{}, *maxConc)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, _ *http.Request) {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		s, c := engine.CacheStats()
		_ = json.NewEncoder(w).Encode(map[string]any{"heapInuseMB": ms.HeapInuse >> 20, "sysMB": ms.Sys >> 20,
			"numGC": ms.NumGC, "stockPrepared": s, "customCached": c})
	})
	mux.HandleFunc("POST /scan", func(w http.ResponseWriter, r *http.Request) {
		var j job
		if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := j.prepare(*stock); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sem <- struct{}{}
		defer func() { <-sem }()
		t := time.Now()
		err := run(r.Context(), j)
		res := map[string]any{"durationSec": time.Since(t).Seconds(), "error": ""}
		if err != nil {
			res["error"] = err.Error()
		}
		_ = json.NewEncoder(w).Encode(res)
	})

	_ = os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	fatal(err)
	fatal(os.Chmod(*socket, 0o600))
	fatal(http.Serve(ln, mux))
}

// run mirrors what `kics scan` builds from its flags (internal/console/scan.go getScanParameters)
// for a prepared job.
func run(ctx context.Context, j job) error {
	if err := os.MkdirAll(j.OutputPath, 0o755); err != nil {
		return err
	}
	p := &scan.Parameters{
		Path: j.Path, QueriesPath: j.QueriesPath, ExcludeQueries: j.ExcludeQueries,
		OutputPath: j.OutputPath, OutputName: j.OutputName, ReportFormats: j.ReportFormats,
		Platform: j.Type, ExcludePlatform: []string{""}, CloudProvider: j.CloudProvider, MaxFileSizeFlag: j.MaxFileSize,
		SecretsRegexesPath: j.SecretsRegexesPath, QueryExecTimeout: j.Timeout,
		PreviewLines: 3, MaxResolverDepth: 15, LibrariesPath: "./assets/libraries",
		ChangedDefaultQueryPath: true, ScanID: uuid.NewString(),
	}
	c, err := scan.NewClient(p, progress.InitializePbBuilder(true, false, true), consolePrinter.NewPrinter(true))
	if err != nil {
		return err
	}
	return c.PerformScan(ctx)
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "kics-serve:", err)
		os.Exit(1)
	}
}
