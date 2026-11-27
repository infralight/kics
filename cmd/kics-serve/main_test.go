package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJobPrepare(t *testing.T) {
	const stock = "/queries/terraform"
	tests := []struct {
		name    string
		in      job
		want    job
		wantErr string
	}{
		{
			name:    "path is required",
			in:      job{OutputPath: "/work"},
			wantErr: "path is required",
		},
		{
			name:    "output-path is required",
			in:      job{Path: []string{"/work/plan.json"}},
			wantErr: "output-path is required",
		},
		{
			name: "fields left out take the defaults",
			in:   job{Path: []string{"/work/plan.json"}, OutputPath: "/work"},
			want: job{
				Path: []string{"/work/plan.json"}, OutputPath: "/work", QueriesPath: []string{stock},
				OutputName: "results", MaxFileSize: 5, Timeout: 60, CloudProvider: []string{""}, Type: []string{""},
			},
		},
		{
			name: "fields that are set are kept",
			in: job{
				Path: []string{"/work/plan.json"}, OutputPath: "/work", QueriesPath: []string{"/work/rules", stock},
				OutputName: "plan", MaxFileSize: 50, Timeout: 120, CloudProvider: []string{"aws"}, Type: []string{"Terraform"},
			},
			want: job{
				Path: []string{"/work/plan.json"}, OutputPath: "/work", QueriesPath: []string{"/work/rules", stock},
				OutputName: "plan", MaxFileSize: 50, Timeout: 120, CloudProvider: []string{"aws"}, Type: []string{"Terraform"},
			},
		},
		{
			name: "output-name is a file name inside output-path",
			in:   job{Path: []string{"/work/plan.json"}, OutputPath: "/work", OutputName: "../../etc/results"},
			want: job{
				Path: []string{"/work/plan.json"}, OutputPath: "/work", QueriesPath: []string{stock},
				OutputName: "results", MaxFileSize: 5, Timeout: 60, CloudProvider: []string{""}, Type: []string{""},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := tt.in
			err := j.prepare(stock)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, j)
		})
	}
}
