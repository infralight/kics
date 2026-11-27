// kics-bench (research harness): run one measurement cell inside a container.
// Every scan of the cell runs at once each round, either as `kics scan` processes (mode cli)
// or as jobs to one long-lived kics-serve child (mode serve). Prints JSON lines.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scanDef struct {
	Name string         `json:"name"`
	Job  map[string]any `json:"job"` // kics-serve job (CLI flag names)
}

func main() {
	mode := flag.String("mode", "cli", "cli|serve")
	cell := flag.String("cell", "", "cell json: list of scans")
	rounds := flag.Int("rounds", 3, "")
	out := flag.String("out", "/tmp/out", "")
	kics := flag.String("kics", "", "kics CLI binary")
	serve := flag.String("serve", "", "kics-serve binary")
	stock := flag.String("stock", "", "stock queries dir")
	serveLog := flag.String("serve-log", "", "also write kics-serve stderr here")
	statsEvery := flag.Bool("stats", false, "query /stats after each round (serve)")
	flag.Parse()

	var scans []scanDef
	b, err := os.ReadFile(*cell)
	must(err)
	must(json.Unmarshal(b, &scans))
	emit(map[string]any{"kind": "env", "nproc": strings.TrimSpace(sh("nproc")), "cpu_max": read("/sys/fs/cgroup/cpu.max"),
		"cpuset": read("/sys/fs/cgroup/cpuset.cpus.effective"), "scans": len(scans)})

	var client *http.Client
	var srvErr *bytes.Buffer
	if *mode == "serve" {
		defer func() {
			if *serveLog != "" {
				_ = os.WriteFile(*serveLog, srvErr.Bytes(), 0o644)
			}
		}()
		sock := "/tmp/kics.sock"
		srvErr = &bytes.Buffer{}
		t := time.Now()
		cpu0 := cpuUsec()
		cmd := exec.Command(*serve, "-socket", sock, "-queries-path", *stock, "-max-concurrent", "64")
		cmd.Stderr, cmd.Stdout = &lockedWriter{w: srvErr}, nil
		must(cmd.Start())
		defer cmd.Process.Kill()
		client = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}}}
		for {
			if r, err := client.Get("http://x/healthz"); err == nil && r.StatusCode == 200 {
				break
			}
			if cmd.ProcessState != nil {
				panic("kics-serve exited: " + srvErr.String())
			}
			time.Sleep(20 * time.Millisecond)
		}
		emit(map[string]any{"kind": "warm", "s": time.Since(t).Seconds(), "cpu_s": float64(cpuUsec()-cpu0) / 1e6,
			"mem_mb": memMB("memory.current")})
	}

	for r := 0; r < *rounds; r++ {
		cpu0 := cpuUsec()
		t := time.Now()
		durs := make([]float64, len(scans))
		errs := make([]string, len(scans))
		timeouts := make([]int, len(scans))
		var wg sync.WaitGroup
		for i, s := range scans {
			wg.Add(1)
			go func(i int, s scanDef) {
				defer wg.Done()
				job := map[string]any{}
				for k, v := range s.Job {
					job[k] = v
				}
				job["output-path"] = filepath.Join(*out, strconv.Itoa(r), s.Name)
				job["output-name"] = "results"
				st := time.Now()
				if *mode == "cli" {
					var stderr bytes.Buffer // with --ci the log (timeouts included) goes to stdout
					cmd := exec.Command(*kics, cliArgs(job)...)
					cmd.Stderr, cmd.Stdout = &stderr, &stderr
					err := cmd.Run()
					if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() < 70 { // findings exit codes (20..60)
						err = nil
					}
					if err != nil {
						errs[i] = err.Error() + " " + stderr.String()
					}
					timeouts[i] = strings.Count(stderr.String(), "Timeout processing")
				} else {
					body, _ := json.Marshal(job)
					resp, err := client.Post("http://x/scan", "application/json", bytes.NewReader(body))
					if err != nil {
						errs[i] = err.Error()
					} else {
						var res map[string]any
						_ = json.NewDecoder(resp.Body).Decode(&res)
						resp.Body.Close()
						if e, _ := res["error"].(string); e != "" {
							errs[i] = e
						}
					}
				}
				durs[i] = time.Since(st).Seconds()
			}(i, s)
		}
		wg.Wait()
		m := map[string]any{"kind": "round", "round": r, "s": time.Since(t).Seconds(), "cpu_s": float64(cpuUsec()-cpu0) / 1e6,
			"scan_s": durs, "errors": errs, "timeouts": timeouts, "mem_current_mb": memMB("memory.current")}
		if *mode == "serve" && *statsEvery {
			if resp, err := client.Get("http://x/stats"); err == nil {
				var st map[string]any
				_ = json.NewDecoder(resp.Body).Decode(&st)
				resp.Body.Close()
				m["stats"] = st
			}
		}
		emit(m)
	}
	if srvErr != nil {
		emit(map[string]any{"kind": "serve_timeouts", "n": strings.Count(srvErr.String(), "Timeout processing")})
	}
	emit(map[string]any{"kind": "mem", "peak_mb": memMB("memory.peak")})
}

// cliArgs builds the `kics scan` command line for a job.
func cliArgs(j map[string]any) []string {
	join := func(k string) string {
		var s []string
		for _, v := range j[k].([]any) {
			s = append(s, v.(string))
		}
		return strings.Join(s, ",")
	}
	a := []string{"scan", "-p", join("path"), "-q", join("queries-path"), "-o", j["output-path"].(string),
		"--output-name", j["output-name"].(string), "--report-formats", "json", "--type", "Terraform",
		"--max-file-size", fmt.Sprint(j["max-file-size"]), "--secrets-regexes-path", j["secrets-regexes-path"].(string),
		"--timeout", fmt.Sprint(j["timeout"]), "--ci"}
	if x := join("exclude-queries"); x != "" {
		a = append(a, "--exclude-queries", x)
	}
	return a
}

type lockedWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func cpuUsec() int64 {
	for _, l := range strings.Split(read("/sys/fs/cgroup/cpu.stat"), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "usage_usec" {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			return n
		}
	}
	return 0
}

func memMB(f string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(read("/sys/fs/cgroup/"+f)), 10, 64)
	return n >> 20
}

func read(p string) string  { b, _ := os.ReadFile(p); return strings.TrimSpace(string(b)) }
func sh(c string) string    { b, _ := exec.Command("sh", "-c", c).Output(); return string(b) }
func emit(m map[string]any) { b, _ := json.Marshal(m); fmt.Println(string(b)) }
func must(err error) {
	if err != nil {
		panic(err)
	}
}
