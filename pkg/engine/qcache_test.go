package engine

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Checkmarx/kics/v2/pkg/engine/source"
	"github.com/Checkmarx/kics/v2/pkg/model"
	"github.com/Checkmarx/kics/v2/test"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/stretchr/testify/require"
)

func stockTerraform(t *testing.T) ([]model.QueryMetadata, source.RegoLibraries, source.RegoLibraries) {
	t.Helper()
	// paths are relative to the repository root, as in the other tests of this package
	require.NoError(t, test.ChangeCurrentDir("kics"))
	src := source.NewFilesystemSource([]string{filepath.FromSlash("./assets/queries/terraform")},
		[]string{"terraform"}, []string{""}, source.LibrariesDefaultBasePath, false)
	queries, err := src.GetQueries(&source.QueryInspectorParameters{})
	require.NoError(t, err)
	common, err := src.GetQueryLibrary("common")
	require.NoError(t, err)
	platform, err := src.GetQueryLibrary("terraform")
	require.NoError(t, err)
	return queries, common, platform
}

func resetShared(t *testing.T) {
	t.Cleanup(func() {
		sharedMu.Lock()
		shared = nil
		sharedMu.Unlock()
	})
}

func eval(t *testing.T, q *rego.PreparedEvalQuery, input string) interface{} {
	t.Helper()
	rs, err := q.Eval(context.Background(), rego.EvalParsedInput(ast.MustParseTerm(input).Value))
	require.NoError(t, err)
	require.Len(t, rs, 1)
	return rs[0].Bindings["result"]
}

// Every stock query must be served from the shared compiler, including the ones whose
// directory name repeats across clouds, and must evaluate like the stock per-query compile.
func TestWarmSharedServesEveryStockQuery(t *testing.T) {
	resetShared(t)
	queries, common, platform := stockTerraform(t)
	loader := QueryLoader{commonLibrary: common, platformLibraries: map[string]source.RegoLibraries{"terraform": platform}}

	names := map[string]int{}
	for i := range queries {
		names[queries[i].Query]++
	}
	var repeated []int
	for i := range queries {
		if names[queries[i].Query] > 1 {
			repeated = append(repeated, i)
		}
	}
	require.NotEmpty(t, repeated, "fixture assumption: some query directory names repeat across clouds")

	const input = `{"document": [{"id": "d1", "file": "f.tf", "resource": {
		"aws_security_group": {"sg": {"ingress": [{"from_port": 22, "to_port": 22, "protocol": "tcp", "cidr_blocks": ["0.0.0.0/0"]}]}},
		"azurerm_network_security_rule": {"r": {"access": "Allow", "direction": "Inbound", "protocol": "TCP",
			"destination_port_range": "22", "source_address_prefix": "*"}}}}]}`
	stock := map[int]interface{}{}
	for _, i := range repeated {
		q, err := loader.LoadQuery(context.Background(), &queries[i]) // cache off: upstream compile
		require.NoError(t, err)
		stock[i] = eval(t, q, input)
	}

	n, err := WarmShared(queries, common, platform, 0)
	require.NoError(t, err)
	require.Equal(t, len(queries), n)
	for i := range queries {
		_, err := loader.LoadQuery(context.Background(), &queries[i])
		require.NoError(t, err, queries[i].Query)
	}
	prepared, custom := CacheStats()
	require.Equal(t, len(queries), prepared)
	require.Zero(t, custom)

	findings := 0
	for _, i := range repeated {
		q, err := loader.LoadQuery(context.Background(), &queries[i])
		require.NoError(t, err)
		got := eval(t, q, input)
		require.Equal(t, stock[i], got, queries[i].Query)
		findings += len(got.([]interface{}))
	}
	require.Positive(t, findings, "the input should trigger at least one of the repeated-name queries")
}

// Custom queries stay out of the shared compiler: a broken one fails alone, an unsafe one is
// rejected, and a cancelled scan does not leave a cached error behind.
func TestCustomQueriesAreIsolated(t *testing.T) {
	resetShared(t)
	queries, common, platform := stockTerraform(t)
	loader := QueryLoader{commonLibrary: common, platformLibraries: map[string]source.RegoLibraries{"terraform": platform}}
	_, err := WarmShared(queries, common, platform, 2)
	require.NoError(t, err)

	custom := func(body string) *model.QueryMetadata {
		return &model.QueryMetadata{Query: "custom", Platform: "terraform", InputData: "{}", Content: "package Cx\n\n" + body}
	}
	_, err = loader.LoadQuery(context.Background(), custom("CxPolicy[result] { this is not rego }"))
	require.Error(t, err)
	_, err = loader.LoadQuery(context.Background(), custom(`CxPolicy[result] { result := http.send({"method": "get", "url": "http://x"}) }`))
	require.ErrorContains(t, err, "unsafe built-in")

	good := custom(`CxPolicy[result] { result := {"documentId": input.document[i].id} }`)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = loader.LoadQuery(cancelled, good)
	require.ErrorIs(t, err, context.Canceled)
	q, err := loader.LoadQuery(context.Background(), good)
	require.NoError(t, err)
	require.Len(t, eval(t, q, `{"document": [{"id": "d1"}]}`), 1)

	_, customCached := CacheStats()
	require.Equal(t, 2, customCached, "LRU keeps at most the configured number of custom queries")
	_, err = loader.LoadQuery(context.Background(), &queries[0])
	require.NoError(t, err, "stock queries still load after custom failures")
}
