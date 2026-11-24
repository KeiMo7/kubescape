package auditlog

import (
	"bytes"
	"fmt"
	"time"
)

// Analyzer runs a streaming behavioral analysis over audit event exports.
type Analyzer struct {
	cfg Config
}

// NewAnalyzer validates the configuration and returns a ready analyzer. An
// illegal config is an error here, at startup, before any input is touched.
func NewAnalyzer(cfg Config) (*Analyzer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid audit configuration: %w", err)
	}
	return &Analyzer{cfg: cfg}, nil
}

// Run streams every input path and returns the merged report. Processing is
// O(1) in input size: each line is parsed, classified and folded into the
// aggregator, then discarded.
func (a *Analyzer) Run(paths []string) (*Report, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no audit input files given")
	}
	det := newDetector(a.cfg)
	agg := newAggregator(a.cfg)
	stats := &SourceStats{}

	var parsed, succeeded, missingTS, outOfOrder int64
	var minTS, maxTS time.Time
	haveTS := false

	err := streamInputs(paths, stats, func(stream string, line []byte) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			return
		}
		ev, perr := parseEvent(line)
		if perr != nil {
			stats.InvalidLines++
			return
		}
		parsed++
		if ev.RequestReceivedTimestamp.IsZero() {
			missingTS++
			return
		}
		ts := ev.RequestReceivedTimestamp.UTC()
		if !haveTS {
			minTS, maxTS, haveTS = ts, ts, true
		} else {
			if ts.Before(minTS) {
				minTS = ts
			}
			if ts.After(maxTS) {
				maxTS = ts
			} else if ts.Before(maxTS) {
				outOfOrder++
			}
		}
		if ev.succeeded() {
			succeeded++
		}
		for _, h := range det.inspect(ev) {
			h.ts = ts
			agg.add(h)
		}
	})
	if err != nil {
		return nil, err
	}

	findings := agg.findings()
	byBehavior := map[string]int{}
	for _, f := range findings {
		byBehavior[f.Behavior]++
	}

	status := "complete"
	if stats.Incomplete {
		status = "partial"
	}

	var warnings []string
	if missingTS > 0 {
		warnings = append(warnings, fmt.Sprintf("%d events had no requestReceivedTimestamp and were excluded from windowed aggregation", missingTS))
	}
	if outOfOrder > 0 {
		warnings = append(warnings, fmt.Sprintf("%d events arrived out of chronological order; window boundaries are taken from the observed minimum/maximum timestamps, not arrival order", outOfOrder))
	}
	if stats.InvalidLines > 0 {
		warnings = append(warnings, fmt.Sprintf("%d lines were not valid audit events and were skipped", stats.InvalidLines))
	}

	rep := &Report{
		APIVersion: reportAPIVersion,
		Kind:       reportKind,
		Metadata: map[string]string{
			"name":       "audit-behavior-report",
			"reportType": "audit-behavior",
		},
		Summary: Summary{
			Status:             status,
			FilesScanned:       stats.FilesScanned,
			EventsParsed:       parsed,
			EventsSucceeded:    succeeded,
			InvalidLines:       stats.InvalidLines,
			MissingTimestamps:  missingTS,
			OutOfOrderEvents:   outOfOrder,
			FindingsTotal:      len(findings),
			FindingsByBehavior: byBehavior,
			Window: WindowSummary{
				WindowSeconds: a.cfg.WindowSeconds,
				Basis:         "tumbling windows aligned to the Unix epoch in UTC; observedStart/observedEnd are the min/max requestReceivedTimestamp seen in the input",
			},
			Warnings:      warnings,
			PartialReason: stats.PartialReason,
		},
		Findings: findings,
	}
	if haveTS {
		rep.Summary.Window.ObservedStart = minTS.Format(time.RFC3339Nano)
		rep.Summary.Window.ObservedEnd = maxTS.Format(time.RFC3339Nano)
	}
	return rep, nil
}
