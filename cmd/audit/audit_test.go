package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeAuditEvents(t *testing.T, dir string) string {
	t.Helper()
	base := time.Date(2026, 3, 9, 14, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	for i := 0; i < 25; i++ {
		fmt.Fprintf(&buf, `{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get","user":{"username":"alice"},"objectRef":{"resource":"secrets","namespace":"prod","name":"s-%02d"},"responseStatus":{"code":200},"requestReceivedTimestamp":%q}`+"\n",
			i, base.Add(time.Duration(i)*time.Second).Format(time.RFC3339Nano))
	}
	p := filepath.Join(dir, "audit.jsonl")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := GetAuditCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestAuditCommandJSON(t *testing.T) {
	dir := t.TempDir()
	input := writeAuditEvents(t, dir)
	out, err := runCmd(t, input)
	if err != nil {
		t.Fatalf("audit command failed: %v\n%s", err, out)
	}
	var rep map[string]interface{}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out)
	}
	if rep["kind"] != "AuditBehaviorReport" {
		t.Fatalf("unexpected kind: %v", rep["kind"])
	}
	summary := rep["summary"].(map[string]interface{})
	if summary["findingsTotal"].(float64) != 1 {
		t.Fatalf("want 1 finding, got %v", summary["findingsTotal"])
	}
}

func TestAuditCommandRejectsBadThreshold(t *testing.T) {
	dir := t.TempDir()
	input := writeAuditEvents(t, dir)
	if _, err := runCmd(t, input, "--bulk-read-threshold", "0"); err == nil {
		t.Fatal("illegal threshold must fail at startup")
	}
	if _, err := runCmd(t, input, "--window", "-5m"); err == nil {
		t.Fatal("illegal window must fail at startup")
	}
	if _, err := runCmd(t, input, "--format", "xml"); err == nil {
		t.Fatal("unsupported format must fail")
	}
}

func TestAuditCommandSARIFAndPretty(t *testing.T) {
	dir := t.TempDir()
	input := writeAuditEvents(t, dir)

	sarifOut := filepath.Join(dir, "report.sarif")
	if _, err := runCmd(t, input, "--format", "sarif", "--output", sarifOut); err != nil {
		t.Fatalf("sarif run failed: %v", err)
	}
	raw, err := os.ReadFile(sarifOut)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("sarif output is not JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Fatalf("not a SARIF 2.1.0 document: %v", doc["version"])
	}

	pretty, err := runCmd(t, input, "--format", "pretty")
	if err != nil {
		t.Fatalf("pretty run failed: %v", err)
	}
	if !strings.Contains(pretty, "bulk-sensitive-read") || !strings.Contains(pretty, "alice") {
		t.Fatalf("pretty output missing finding:\n%s", pretty)
	}
}

func TestAuditCommandPartialExitError(t *testing.T) {
	dir := t.TempDir()
	input := writeAuditEvents(t, dir)
	corrupt := filepath.Join(dir, "broken.tgz")
	if err := os.WriteFile(corrupt, []byte("not a gzip stream"), 0o600); err != nil {
		t.Fatal(err)
	}
	outFile := filepath.Join(dir, "report.json")
	_, err := runCmd(t, input, corrupt, "--output", outFile)
	if err == nil {
		t.Fatal("corrupt archive must not exit successfully")
	}
	// ...but the partial report must still have been written and marked.
	raw, rerr := os.ReadFile(outFile)
	if rerr != nil {
		t.Fatalf("partial report was not written: %v", rerr)
	}
	if !strings.Contains(string(raw), `"status": "partial"`) {
		t.Fatal("partial report must be marked incomplete")
	}
}
