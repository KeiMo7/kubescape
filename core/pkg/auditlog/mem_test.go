package auditlog

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// generateAuditFile streams a synthetic audit export of approximately
// targetBytes to disk without holding it in memory. The event mix exercises
// every detector path while keeping the number of distinct subjects, windows
// and objects bounded — which is exactly the state the analyzer must keep
// O(1) in input size.
func generateAuditFile(t testing.TB, path string, targetBytes int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	defer w.Flush()

	base := time.Date(2026, 3, 9, 0, 0, 0, 0, time.UTC)
	var written int64
	i := 0
	for written < targetBytes {
		ts := base.Add(time.Duration(i%86400) * time.Second).UTC().Format(time.RFC3339Nano)
		var line string
		switch i % 7 {
		case 0: // sensitive read, bounded object set (500 distinct secrets)
			line = fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get","user":{"username":"user-%d"},"objectRef":{"resource":"secrets","namespace":"prod","name":"secret-%d"},"responseStatus":{"code":200},"requestReceivedTimestamp":%q}`,
				i%200, i%500, ts)
		case 1: // non-sensitive read
			line = fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get","user":{"username":"user-%d"},"objectRef":{"resource":"configmaps","namespace":"default","name":"cm-%d"},"responseStatus":{"code":200},"requestReceivedTimestamp":%q}`,
				i%200, i%50, ts)
		case 2: // platform list
			line = fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"list","user":{"username":"system:serviceaccount:kube-system:controller"},"objectRef":{"resource":"pods"},"responseStatus":{"code":200},"requestReceivedTimestamp":%q}`, ts)
		case 3: // failed attempt
			line = fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get","user":{"username":"mallory"},"objectRef":{"resource":"secrets","namespace":"prod","name":"secret-%d"},"responseStatus":{"code":403},"requestReceivedTimestamp":%q}`,
				i%500, ts)
		case 4: // exec, bounded pod set
			line = fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"create","user":{"username":"debugger-%d"},"objectRef":{"resource":"pods","subresource":"exec","namespace":"prod","name":"pod-%d"},"responseStatus":{"code":101},"requestReceivedTimestamp":%q}`,
				i%20, i%100, ts)
		case 5: // anonymous
			line = fmt.Sprintf(`{"kind":"Event","apiVersion":"audit.k8s.io/v1","verb":"get","user":{"username":"system:anonymous","groups":["system:unauthenticated"]},"objectRef":{"resource":"configmaps","namespace":"kube-public","name":"cm-%d"},"responseStatus":{"code":200},"requestReceivedTimestamp":%q}`,
				i%10, ts)
		default: // invalid line, must be skipped and counted
			line = `{"kind":"Event","apiVersion":"audit.k8s.io/v1",BROKEN`
		}
		n, _ := w.WriteString(line + "\n")
		written += int64(n)
		i++
	}
}

// readPeakRSS returns the process high-water mark RSS in bytes (Linux).
func readPeakRSS(t testing.TB) int64 {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Skipf("cannot read /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			fields := strings.Fields(line)
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatalf("parsing VmHWM: %v", err)
			}
			return kb * 1024
		}
	}
	t.Skip("VmHWM not found")
	return 0
}

// runMemoryCheck generates an input of the given size, analyzes it, and
// returns the peak RSS observed. The caller asserts the bound.
func runMemoryCheck(t testing.TB, targetBytes int64) (peak int64, parsed int64) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "big.jsonl")
	generateAuditFile(t, path, targetBytes)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("input file size: %.1f MB", float64(st.Size())/(1<<20))

	an, err := NewAnalyzer(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	rep, err := an.Run([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	peak = readPeakRSS(t)
	t.Logf("peak RSS (VmHWM): %.1f MB; events parsed: %d; findings: %d",
		float64(peak)/(1<<20), rep.Summary.EventsParsed, rep.Summary.FindingsTotal)
	return peak, rep.Summary.EventsParsed
}

// TestStreamingMemoryBound proves memory does not grow with input size: a
// ~100 MB export must be processed within a fixed, small RSS budget.
func TestStreamingMemoryBound(t *testing.T) {
	peak, parsed := runMemoryCheck(t, 100<<20) // 100 MiB
	if parsed == 0 {
		t.Fatal("no events parsed")
	}
	const budget = 256 << 20 // 256 MiB
	if peak > budget {
		t.Fatalf("peak RSS %d bytes exceeds budget %d bytes", peak, budget)
	}
}

// TestStreamingMemoryBound1GiB is the billion-byte variant. It is opt-in
// (AUDIT_MEMTEST_1G=1) because generating and scanning 1 GiB takes a while;
// run it explicitly for release verification.
func TestStreamingMemoryBound1GiB(t *testing.T) {
	if os.Getenv("AUDIT_MEMTEST_1G") != "1" {
		t.Skip("set AUDIT_MEMTEST_1G=1 to run the 1 GiB streaming test")
	}
	peak, parsed := runMemoryCheck(t, 1<<30) // 1 GiB
	if parsed == 0 {
		t.Fatal("no events parsed")
	}
	const budget = 256 << 20 // 256 MiB
	if peak > budget {
		t.Fatalf("peak RSS %d bytes exceeds budget %d bytes for 1 GiB input", peak, budget)
	}
}
