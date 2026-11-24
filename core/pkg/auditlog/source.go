package auditlog

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SourceStats accumulates per-run counters that must survive partial
// failures: a corrupt archive must not silently zero the counters.
type SourceStats struct {
	FilesScanned  int      `json:"filesScanned"`
	LinesRead     int64    `json:"linesRead"`
	InvalidLines  int64    `json:"invalidLines"`
	Sources       []string `json:"sources"`
	Incomplete    bool     `json:"incomplete"`
	PartialReason []string `json:"partialReason,omitempty"`
}

// lineHandler consumes one raw line from a named stream inside one of the
// input files (a file, a gzip member, or an archive entry).
type lineHandler func(stream string, line []byte)

// streamInputs walks every input path and feeds every line of every contained
// stream to handle, one line at a time. Memory use is bounded by the longest
// single line, not by input size. A corrupted archive records a partial
// marker in stats and processing continues with the next input; lines already
// delivered are kept.
func streamInputs(paths []string, stats *SourceStats, handle lineHandler) error {
	for _, p := range paths {
		if err := streamOnePath(p, stats, handle); err != nil {
			return err
		}
	}
	return nil
}

func streamOnePath(path string, stats *SourceStats, handle lineHandler) error {
	f, err := os.Open(path)
	if err != nil {
		// A missing/unreadable top-level input is a usage error, not a
		// degraded scan: fail fast with a clear message.
		return fmt.Errorf("opening audit input %q: %w", path, err)
	}
	defer f.Close()

	lower := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			markPartial(stats, fmt.Sprintf("%s: not a valid gzip stream: %v", path, err))
			return nil
		}
		defer gz.Close()
		streamTar(path, gz, stats, handle)
	case strings.HasSuffix(lower, ".tar"):
		streamTar(path, f, stats, handle)
	case strings.HasSuffix(lower, ".zip"):
		return streamZip(path, stats, handle)
	case strings.HasSuffix(lower, ".gz"):
		gz, err := gzip.NewReader(f)
		if err != nil {
			markPartial(stats, fmt.Sprintf("%s: not a valid gzip stream: %v", path, err))
			return nil
		}
		defer gz.Close()
		streamLines(path, gz, stats, handle)
	default:
		streamLines(path, f, stats, handle)
	}
	return nil
}

func streamTar(name string, r io.Reader, stats *SourceStats, handle lineHandler) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			markPartial(stats, fmt.Sprintf("%s: corrupt tar archive: %v", name, err))
			return
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		streamLines(name+"!"+hdr.Name, tr, stats, handle)
	}
}

func streamZip(path string, stats *SourceStats, handle lineHandler) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		markPartial(stats, fmt.Sprintf("%s: not a valid zip archive: %v", path, err))
		return nil
	}
	defer zr.Close()
	for _, ze := range zr.File {
		if ze.FileInfo().IsDir() {
			continue
		}
		rc, err := ze.Open()
		if err != nil {
			markPartial(stats, fmt.Sprintf("%s!%s: cannot open zip entry: %v", path, ze.Name, err))
			continue
		}
		streamLines(path+"!"+ze.Name, rc, stats, handle)
		rc.Close()
	}
	return nil
}

// streamLines reads r line by line with no line-length cap and counts every
// line. A read error mid-stream marks the scan partial but keeps the lines
// already delivered.
func streamLines(name string, r io.Reader, stats *SourceStats, handle lineHandler) {
	stats.FilesScanned++
	stats.Sources = append(stats.Sources, name)
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			stats.LinesRead++
			handle(name, line)
		}
		if err == nil {
			continue
		}
		if err != io.EOF {
			markPartial(stats, fmt.Sprintf("%s: read error: %v", name, err))
		}
		return
	}
}

func markPartial(stats *SourceStats, reason string) {
	stats.Incomplete = true
	stats.PartialReason = append(stats.PartialReason, reason)
}
