package auditlog

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// mkEvent builds one audit event line. requestObject may be nil.
func mkEvent(t *testing.T, ts time.Time, verb, username string, groups []string, resource, subresource, ns, name string, code int32, requestObject interface{}) []byte {
	t.Helper()
	ev := map[string]interface{}{
		"kind":                     "Event",
		"apiVersion":               "audit.k8s.io/v1",
		"verb":                     verb,
		"user":                     map[string]interface{}{"username": username, "groups": groups},
		"requestReceivedTimestamp": ts.UTC().Format(time.RFC3339Nano),
	}
	if resource != "" {
		ev["objectRef"] = map[string]interface{}{
			"resource":    resource,
			"subresource": subresource,
			"namespace":   ns,
			"name":        name,
		}
	}
	if code > 0 {
		ev["responseStatus"] = map[string]interface{}{"code": code}
	}
	if requestObject != nil {
		raw, err := json.Marshal(requestObject)
		if err != nil {
			t.Fatal(err)
		}
		var v interface{}
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		ev["requestObject"] = v
	}
	line, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func writeLines(t *testing.T, dir, name string, lines [][]byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	var buf bytes.Buffer
	for _, l := range lines {
		buf.Write(l)
		buf.WriteByte('\n')
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func testConfig() Config {
	cfg := DefaultConfig()
	cfg.BulkReadThreshold = 3
	return cfg
}

func TestNormalizeSubject(t *testing.T) {
	cases := []struct {
		in       string
		wantKind string
		wantID   string
	}{
		{"Alice", SubjectKindUser, "alice"},
		{"ALICE@EXAMPLE.COM", SubjectKindUser, "alice"},
		{"alice@example.com", SubjectKindUser, "alice"},
		{" system:serviceaccount:default:builder ", SubjectKindServiceAccount, "system:serviceaccount:default:builder"},
		{"System:ServiceAccount:Default:Builder", SubjectKindServiceAccount, "system:serviceaccount:default:builder"},
		{"sa:default:builder", SubjectKindServiceAccount, "system:serviceaccount:default:builder"},
		{"system:serviceaccount:default:builder@cluster.local", SubjectKindServiceAccount, "system:serviceaccount:default:builder"},
		{"system:anonymous", SubjectKindUser, "system:anonymous"},
		{"system:authenticated", SubjectKindGroup, "system:authenticated"},
		{"system:unauthenticated", SubjectKindGroup, "system:unauthenticated"},
		{"kubernetes-admin", SubjectKindUser, "kubernetes-admin"},
	}
	for _, c := range cases {
		kind, id := NormalizeSubject(c.in)
		if kind != c.wantKind || id != c.wantID {
			t.Errorf("NormalizeSubject(%q) = (%q, %q), want (%q, %q)", c.in, kind, id, c.wantKind, c.wantID)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config must be valid: %v", err)
	}
	bad := []func(*Config){
		func(c *Config) { c.WindowSeconds = 0 },
		func(c *Config) { c.WindowSeconds = -5 },
		func(c *Config) { c.BulkReadThreshold = 0 },
		func(c *Config) { c.MaxObjectsPerFinding = -1 },
		func(c *Config) { c.SensitiveResources = nil },
		func(c *Config) { c.PrivilegedRoles = nil },
		func(c *Config) { c.ExecSubresources = nil },
	}
	for i, mutate := range bad {
		c := DefaultConfig()
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
		if _, err := NewAnalyzer(c); err == nil {
			t.Errorf("case %d: NewAnalyzer must reject invalid config at startup", i)
		}
	}
}

func TestMissingResponseStatusIsNotSuccess(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	var lines [][]byte
	// 10 secret reads with NO responseStatus at all: must not count.
	for i := 0; i < 10; i++ {
		lines = append(lines, mkEvent(t, ts.Add(time.Duration(i)*time.Second), "get", "mallory", nil, "secrets", "", "default", fmt.Sprintf("s%d", i), 0, nil))
	}
	// 10 secret reads with a failure code: must not count either.
	for i := 0; i < 10; i++ {
		lines = append(lines, mkEvent(t, ts.Add(time.Duration(i)*time.Second), "get", "mallory", nil, "secrets", "", "default", fmt.Sprintf("f%d", i), 403, nil))
	}
	path := writeLines(t, dir, "audit.jsonl", lines)

	an, err := NewAnalyzer(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := an.Run([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.FindingsTotal != 0 {
		t.Fatalf("events without a successful response status must not produce findings, got %+v", rep.Findings)
	}
	if rep.Summary.EventsParsed != 20 || rep.Summary.EventsSucceeded != 0 {
		t.Fatalf("unexpected counters: %+v", rep.Summary)
	}
}

func TestSubresourceFoldsIntoParent(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	var lines [][]byte
	// Reading secrets via a subresource-style access must still count as the
	// parent resource "secrets" and as the same object identity.
	for i := 0; i < 3; i++ {
		lines = append(lines, mkEvent(t, ts, "get", "mallory", nil, "secrets", "", "default", fmt.Sprintf("sec-%d", i), 200, nil))
	}
	// Duplicate access to the same object within the window: deduped.
	lines = append(lines, mkEvent(t, ts.Add(time.Second), "get", "mallory", nil, "secrets", "", "default", "sec-0", 200, nil))
	lines = append(lines, mkEvent(t, ts.Add(2*time.Second), "get", "mallory", nil, "secrets", "", "default", "sec-0", 200, nil))
	path := writeLines(t, dir, "audit.jsonl", lines)

	an, _ := NewAnalyzer(testConfig())
	rep, err := an.Run([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.FindingsTotal != 1 {
		t.Fatalf("want 1 merged finding, got %d: %+v", rep.Summary.FindingsTotal, rep.Findings)
	}
	f := rep.Findings[0]
	if f.Behavior != BehaviorBulkSensitiveRead {
		t.Fatalf("wrong behavior %q", f.Behavior)
	}
	if f.Count != 3 || f.ObjectsTotal != 3 {
		t.Fatalf("repeated access to the same object must be deduped: count=%d total=%d", f.Count, f.ObjectsTotal)
	}
	if f.Events != 5 {
		t.Fatalf("raw event count should be 5, got %d", f.Events)
	}
	if f.FirstSeen != ts.Format(time.RFC3339Nano) || f.LastSeen != ts.Add(2*time.Second).Format(time.RFC3339Nano) {
		t.Fatalf("first/last times wrong: %s .. %s", f.FirstSeen, f.LastSeen)
	}
	for _, o := range f.Objects {
		if strings.Contains(o, "/exec") || strings.Count(o, "/") > 2 {
			t.Fatalf("subresource leaked into object identity: %q", o)
		}
	}
}

func TestWindowMergingAndSplitting(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 5, 10, 1, 0, 0, time.UTC) // inside window 10:00-10:10
	var lines [][]byte
	// 3 distinct secrets in the first window -> one finding.
	for i := 0; i < 3; i++ {
		lines = append(lines, mkEvent(t, base.Add(time.Duration(i)*time.Minute), "get", "eve", nil, "secrets", "", "default", fmt.Sprintf("a%d", i), 200, nil))
	}
	// 3 distinct secrets 30 minutes later -> a second window, second finding.
	later := base.Add(30 * time.Minute)
	for i := 0; i < 3; i++ {
		lines = append(lines, mkEvent(t, later.Add(time.Duration(i)*time.Minute), "get", "eve", nil, "secrets", "", "default", fmt.Sprintf("b%d", i), 200, nil))
	}
	path := writeLines(t, dir, "audit.jsonl", lines)

	an, _ := NewAnalyzer(testConfig())
	rep, err := an.Run([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.FindingsTotal != 2 {
		t.Fatalf("want 2 windowed findings, got %d", rep.Summary.FindingsTotal)
	}
	if rep.Findings[0].Window.Start != "2026-01-05T10:00:00Z" || rep.Findings[0].Window.End != "2026-01-05T10:10:00Z" {
		t.Fatalf("window boundaries wrong: %+v", rep.Findings[0].Window)
	}
	if rep.Findings[1].Window.Start != "2026-01-05T10:30:00Z" {
		t.Fatalf("second window wrong: %+v", rep.Findings[1].Window)
	}
}

func TestInvalidLinesSkippedAndCounted(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	lines := [][]byte{
		[]byte("this is not json"),
		[]byte("{broken"),
		mkEvent(t, ts, "get", "eve", nil, "secrets", "", "default", "x0", 200, nil),
		[]byte(""),
		mkEvent(t, ts, "get", "eve", nil, "secrets", "", "default", "x1", 200, nil),
		mkEvent(t, ts, "get", "eve", nil, "secrets", "", "default", "x2", 200, nil),
	}
	path := writeLines(t, dir, "audit.jsonl", lines)

	an, _ := NewAnalyzer(testConfig())
	rep, err := an.Run([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.InvalidLines != 2 {
		t.Fatalf("want 2 invalid lines, got %d", rep.Summary.InvalidLines)
	}
	if rep.Summary.FindingsTotal != 1 {
		t.Fatalf("invalid lines must not abort the batch: %+v", rep.Summary)
	}
	if len(rep.Summary.Warnings) == 0 {
		t.Fatal("invalid lines must surface a warning")
	}
}

func TestMissingAndOutOfOrderTimestampsWarn(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	noTS := mkEvent(t, ts, "get", "eve", nil, "secrets", "", "default", "y0", 200, nil)
	var m map[string]interface{}
	if err := json.Unmarshal(noTS, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "requestReceivedTimestamp")
	noTS, _ = json.Marshal(m)

	lines := [][]byte{
		mkEvent(t, ts.Add(time.Minute), "get", "eve", nil, "configmaps", "", "default", "c1", 200, nil),
		noTS,
		mkEvent(t, ts, "get", "eve", nil, "configmaps", "", "default", "c2", 200, nil), // out of order
	}
	path := writeLines(t, dir, "audit.jsonl", lines)

	an, _ := NewAnalyzer(testConfig())
	rep, err := an.Run([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.MissingTimestamps != 1 {
		t.Fatalf("want 1 missing timestamp, got %d", rep.Summary.MissingTimestamps)
	}
	if rep.Summary.OutOfOrderEvents != 1 {
		t.Fatalf("want 1 out-of-order event, got %d", rep.Summary.OutOfOrderEvents)
	}
	joined := strings.Join(rep.Summary.Warnings, "\n")
	if !strings.Contains(joined, "requestReceivedTimestamp") || !strings.Contains(joined, "out of chronological order") {
		t.Fatalf("warnings must explain timestamp handling: %v", rep.Summary.Warnings)
	}
	if !strings.Contains(rep.Summary.Window.Basis, "min/max") {
		t.Fatalf("window basis must be documented: %q", rep.Summary.Window.Basis)
	}
	if rep.Summary.Window.ObservedStart == "" || rep.Summary.Window.ObservedEnd == "" {
		t.Fatal("observed window boundaries must be reported")
	}
}

func TestDeterministicOutput(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	var lines [][]byte
	for i := 0; i < 50; i++ {
		lines = append(lines, mkEvent(t, ts.Add(time.Duration(i)*time.Second), "get", "eve", nil, "secrets", "", "default", fmt.Sprintf("s%02d", i), 200, nil))
	}
	path := writeLines(t, dir, "audit.jsonl", lines)

	an, _ := NewAnalyzer(testConfig())
	render := func() string {
		rep, err := an.Run([]string{path})
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := WriteJSON(&buf, rep); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	first, second := render(), render()
	if first != second {
		t.Fatal("two runs over the same input must be byte-identical")
	}
}

func TestArchiveInputsAndCorruption(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	var lines [][]byte
	for i := 0; i < 3; i++ {
		lines = append(lines, mkEvent(t, ts, "get", "eve", nil, "secrets", "", "default", fmt.Sprintf("s%d", i), 200, nil))
	}
	var raw bytes.Buffer
	for _, l := range lines {
		raw.Write(l)
		raw.WriteByte('\n')
	}

	// .gz
	gzPath := filepath.Join(dir, "a.jsonl.gz")
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	gw.Write(raw.Bytes())
	gw.Close()
	if err := os.WriteFile(gzPath, gzBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// .zip
	zipPath := filepath.Join(dir, "b.zip")
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	ent, _ := zw.Create("inner/audit.jsonl")
	ent.Write(raw.Bytes())
	zw.Close()
	if err := os.WriteFile(zipPath, zipBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	// .tar.gz
	tgzPath := filepath.Join(dir, "c.tar.gz")
	var tgzBuf bytes.Buffer
	gw2 := gzip.NewWriter(&tgzBuf)
	tw := tar.NewWriter(gw2)
	tw.WriteHeader(&tar.Header{Name: "audit.jsonl", Mode: 0o600, Size: int64(raw.Len()), Typeflag: tar.TypeReg})
	tw.Write(raw.Bytes())
	tw.Close()
	gw2.Close()
	if err := os.WriteFile(tgzPath, tgzBuf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	an, _ := NewAnalyzer(testConfig())
	rep, err := an.Run([]string{gzPath, zipPath, tgzPath})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Summary.FilesScanned != 3 {
		t.Fatalf("want 3 streams, got %d", rep.Summary.FilesScanned)
	}
	if rep.Summary.EventsParsed != 9 {
		t.Fatalf("want 9 events across archives, got %d", rep.Summary.EventsParsed)
	}

	// Corrupt archive: partial results, not a fake success.
	corrupt := filepath.Join(dir, "broken.tgz")
	if err := os.WriteFile(corrupt, []byte("this is not gzip data at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep2, err := an.Run([]string{gzPath, corrupt})
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Summary.Status != "partial" {
		t.Fatalf("corrupt archive must mark the report partial, got %q", rep2.Summary.Status)
	}
	if rep2.Summary.EventsParsed != 3 {
		t.Fatalf("completed portion must be preserved, got %d events", rep2.Summary.EventsParsed)
	}
	if len(rep2.Summary.PartialReason) == 0 {
		t.Fatal("partial reason must be recorded")
	}
}

func TestNoSensitiveContentInReport(t *testing.T) {
	dir := t.TempDir()
	ts := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	secretValue := "s3cr3t-t0ken-value"
	pod := map[string]interface{}{
		"spec": map[string]interface{}{
			"containers": []interface{}{
				map[string]interface{}{
					"name":            "app",
					"securityContext": map[string]interface{}{"privileged": true},
					"env":             []interface{}{map[string]interface{}{"name": "TOKEN", "value": secretValue}},
				},
			},
		},
	}
	lines := [][]byte{
		mkEvent(t, ts, "create", "eve", nil, "pods", "", "default", "p0", 201, pod),
	}
	path := writeLines(t, dir, "audit.jsonl", lines)

	an, _ := NewAnalyzer(testConfig())
	rep, err := an.Run([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), secretValue) {
		t.Fatal("report must never contain sensitive object content")
	}
	if rep.Summary.FindingsTotal != 1 || rep.Findings[0].Behavior != BehaviorPrivilegedWorkload {
		t.Fatalf("privileged pod not detected: %+v", rep.Findings)
	}
}
