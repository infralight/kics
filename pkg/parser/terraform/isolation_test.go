package terraform

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Checkmarx/kics/v2/pkg/model"
	"github.com/stretchr/testify/require"
)

func parseTF(t *testing.T, p *Parser, dir, name, content string) []model.Document {
	t.Helper()
	file := filepath.Join(dir, name, "main.tf")
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o755))
	require.NoError(t, os.WriteFile(file, []byte(content), 0o600))
	resolved, err := p.Resolve([]byte(content), file, false, 15)
	require.NoError(t, err)
	docs, _, err := p.Parse(file, resolved)
	require.NoError(t, err)
	return docs
}

// One scan must not change how the next scan in the same process parses its files.
// With the old package-global variable map, the unknown root `local` written while
// parsing scan A made scan B render "${lower(local.name)}" instead of "local.name".
func TestParsersDoNotShareVariables(t *testing.T) {
	const scanA = `resource "aws_s3_bucket" "a" {
  bucket = lower(local.name_a)
}
`
	const scanB = `resource "aws_s3_bucket" "b" {
  bucket = lower(local.name)
}
`
	fresh := parseTF(t, NewDefault(), t.TempDir(), "b", scanB)

	dir := t.TempDir()
	parseTF(t, NewDefault(), dir, "a", scanA)
	afterA := parseTF(t, NewDefault(), dir, "b", scanB)

	asJSON := func(docs []model.Document) string {
		b, err := json.Marshal(docs)
		require.NoError(t, err)
		return string(b)
	}
	require.Contains(t, asJSON(fresh), `"bucket":"local.name"`)
	require.Equal(t, asJSON(fresh), asJSON(afterA))
}
