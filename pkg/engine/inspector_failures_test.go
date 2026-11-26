package engine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/Checkmarx/kics/v2/internal/tracker"
	"github.com/Checkmarx/kics/v2/pkg/detector"
	"github.com/Checkmarx/kics/v2/pkg/model"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A decode that runs out of time must fail the query, not return a prefix of its findings as complete.
func TestDecodeQueryResultsTimeout(t *testing.T) {
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	oneFinding := rego.ResultSet{{Bindings: map[string]interface{}{"result": []interface{}{map[string]interface{}{}}}}}
	noFindings := rego.ResultSet{{Bindings: map[string]interface{}{"result": []interface{}{}}}}
	cases := []struct {
		name    string
		ctx     context.Context
		results rego.ResultSet
		wantErr error
	}{
		// Mutation: only log the timeout; the query then reports what it decoded as complete.
		{name: "the decode deadline passed", ctx: expired, results: oneFinding, wantErr: ErrDecodeTimeout},
		{name: "nothing left to decode", ctx: context.Background(), results: noFindings},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Inspector{failedQueries: map[string]error{}}
			qctx := &QueryContext{Query: &PreparedQuery{Metadata: model.QueryMetadata{Query: "q", Platform: "Terraform"}}}
			_, err := c.DecodeQueryResults(qctx, tc.ctx, tc.results)
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.True(t, errors.Is(err, tc.wantErr), "got %v", err)
		})
	}
}

// The collector and the workers record failures concurrently; run with -race.
func TestRecordFailedQueryIsSafeAndKeepsTheFirstError(t *testing.T) {
	cases := []struct {
		name      string
		overwrite bool
		wantErr   string
	}{
		{name: "a worker keeps the first error", overwrite: false, wantErr: "first"},
		{name: "the collector overwrites", overwrite: true, wantErr: "second"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Inspector{failedQueries: map[string]error{}}
			c.recordFailedQuery("q", errors.New("first"), false)
			c.recordFailedQuery("q", errors.New("second"), tc.overwrite)
			require.EqualError(t, c.GetFailedQueries()["q"], tc.wantErr)

			var wg sync.WaitGroup
			for i := range 50 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c.recordFailedQuery(fmt.Sprintf("q%d", i), errors.New("x"), i%2 == 0)
					_ = c.GetFailedQueries()
				}()
			}
			wg.Wait()
			require.Len(t, c.GetFailedQueries(), 51)
			c.ResetFailedQueries()
			require.Empty(t, c.GetFailedQueries())
		})
	}
}

// Workers build findings concurrently with one shared line detector; run with -race.
// Mutation: keep the detector.SetupLogs call; every worker writes the detector's shared logger field.
func TestDefaultVulnerabilityBuilderIsSafeAcrossWorkers(t *testing.T) {
	cases := []struct {
		name    string
		workers int
	}{
		{name: "eight workers", workers: 8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shared := detector.NewDetectLine(3)
			ctx := &QueryContext{
				scanID: "scan",
				Query: &PreparedQuery{Metadata: model.QueryMetadata{Query: "q", Metadata: map[string]interface{}{
					"severity": model.SeverityInfo, "issueType": "IncorrectValue", "searchKey": "k"}}},
				Files: map[string]model.FileMetadata{"doc": {LinesOriginalData: &[]string{}}},
			}
			var wg sync.WaitGroup
			for range tc.workers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := DefaultVulnerabilityBuilder(ctx, &tracker.CITracker{}, map[string]interface{}{"documentId": "doc"},
						shared, false, false, map[string]TransitionQueryInfo{})
					assert.NoError(t, err)
				}()
			}
			wg.Wait()
		})
	}
}
