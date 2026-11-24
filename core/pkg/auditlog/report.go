package auditlog

import (
	"time"
)

// Window is a half-open aggregation interval [Start, End), aligned to the
// Unix epoch in UTC.
type Window struct {
	Start time.Time `json:"-"`
	End   time.Time `json:"-"`
}

// WindowJSON is the serialized form of a Window.
type WindowJSON struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

func (w Window) json() WindowJSON {
	return WindowJSON{
		Start: w.Start.UTC().Format(time.RFC3339),
		End:   w.End.UTC().Format(time.RFC3339),
	}
}

// Finding is one merged behavioral conclusion: one subject, one behavior, one
// window, with the count, first/last timestamps and the identifiers of the
// objects involved. It contains no object content and no credential material.
type Finding struct {
	Behavior         string     `json:"behavior"`
	Subject          string     `json:"subject"`
	SubjectKind      string     `json:"subjectKind"`
	Window           WindowJSON `json:"window"`
	Count            int        `json:"count"`
	Events           int64      `json:"events"`
	FirstSeen        string     `json:"firstSeen"`
	LastSeen         string     `json:"lastSeen"`
	Detail           string     `json:"detail,omitempty"`
	Objects          []string   `json:"objects"`
	ObjectsTotal     int        `json:"objectsTotal"`
	ObjectsTruncated bool       `json:"objectsTruncated,omitempty"`
}

// Summary captures run-level counters and the exact window basis so every
// conclusion in the report can be re-checked against the raw export.
type Summary struct {
	Status             string         `json:"status"` // "complete" or "partial"
	FilesScanned       int            `json:"filesScanned"`
	EventsParsed       int64          `json:"eventsParsed"`
	EventsSucceeded    int64          `json:"eventsSucceeded"`
	InvalidLines       int64          `json:"invalidLines"`
	MissingTimestamps  int64          `json:"missingTimestamps"`
	OutOfOrderEvents   int64          `json:"outOfOrderEvents"`
	FindingsTotal      int            `json:"findingsTotal"`
	FindingsByBehavior map[string]int `json:"findingsByBehavior"`
	Window             WindowSummary  `json:"window"`
	Warnings           []string       `json:"warnings,omitempty"`
	PartialReason      []string       `json:"partialReason,omitempty"`
}

// WindowSummary states the observed time span and how window boundaries were
// derived, so reviewers can see exactly how events were bucketed.
type WindowSummary struct {
	ObservedStart string `json:"observedStart,omitempty"`
	ObservedEnd   string `json:"observedEnd,omitempty"`
	WindowSeconds int64  `json:"windowSeconds"`
	Basis         string `json:"basis"`
}

// Report is the top-level audit behavior report. Its shape mirrors the
// kubescape posture-report envelope (apiVersion/kind/metadata/summary plus a
// results list) so existing output channels can consume it. It is fully
// derived from the input: identical input yields byte-identical output.
type Report struct {
	APIVersion string            `json:"apiVersion"`
	Kind       string            `json:"kind"`
	Metadata   map[string]string `json:"metadata"`
	Summary    Summary           `json:"summary"`
	Findings   []Finding         `json:"findings"`
}

const (
	reportAPIVersion = "audit.kubescape.io/v1"
	reportKind       = "AuditBehaviorReport"
)
