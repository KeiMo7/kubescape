package diff

import "encoding/json"

// Stable categories used by framework-aware report-set comparisons. Tests and
// CI integrations should depend on these values rather than human-readable
// reasons, which may be clarified without changing the category.
const (
	CategoryAggregateNew          = "aggregate.new"
	CategoryAggregateResolved     = "aggregate.resolved"
	CategoryAggregateUnchanged    = "aggregate.unchanged"
	CategoryAggregateIncomparable = "aggregate.incomparable"

	CategoryFrameworkNew          = "framework.new"
	CategoryFrameworkResolved     = "framework.resolved"
	CategoryFrameworkUnchanged    = "framework.unchanged"
	CategoryFrameworkIncomparable = "framework.incomparable"
	CategoryCoverageFrameworkSide = "coverage.framework_single_side"
	CategoryCoverageControlScope  = "coverage.control_out_of_scope"
	CategoryCoverageIncomplete    = "coverage.evaluation_incomplete"
	CategoryCoverageScopeMismatch = "coverage.scope_mismatch"

	CategoryConflictEvidence   = "conflict.evidence_conclusion"
	CategoryIdentityMismatch   = "identity.mismatch"
	CategoryDuplicateReport    = "source.duplicate_report"
	CategoryMetadataAdjustment = "metadata.severity_normalized"

	SideBase = "base"
	SideHead = "head"

	identitySystemAnonymized = "anonymized"
	identitySystemCleartext  = "cleartext"
	identitySystemUnknown    = "unknown"

	targetIdentityUnknown = "target:unknown"
	// UnattributedFramework groups controls that do not declare framework
	// membership. It is intentionally stable and machine-readable.
	UnattributedFramework = "_unattributed"
)

// Identity is the five-layer identity required before two findings may be
// treated as the same object. The evidence layer includes all evidence
// coordinates, not merely a path string, so distinct evidence types never
// collide.
type Identity struct {
	TargetID           string `json:"targetID,omitempty"`
	ResourceID         string `json:"resourceID"`
	ControlID          string `json:"controlID"`
	RuleName           string `json:"ruleName,omitempty"`
	EvidenceType       string `json:"evidenceType,omitempty"`
	Path               string `json:"path,omitempty"`
	EvidenceResourceID string `json:"evidenceResourceID,omitempty"`
}

func identityFromChange(change ControlChange) Identity {
	return Identity{
		TargetID:           change.TargetID,
		ResourceID:         change.ResourceID,
		ControlID:          change.ControlID,
		RuleName:           change.RuleName,
		EvidenceType:       change.EvidenceType,
		Path:               change.Path,
		EvidenceResourceID: change.EvidenceResourceID,
	}
}

func (id Identity) cacheKey() string {
	// JSON field order is fixed by the struct. Length-prefixing is unnecessary
	// because encoding/json quotes and escapes each string; two different
	// structs cannot produce the same JSON value.
	data, _ := json.Marshal(id)
	return string(data)
}

// Source is the non-sensitive provenance for one unique report. File paths are
// deliberately absent: callers need a stable handle for conflict output, while
// read/parse errors still name the offending argument.
type Source struct {
	ID              string   `json:"id"`
	SHA256          string   `json:"sha256"`
	Frameworks      []string `json:"frameworks,omitempty"`
	TargetID        string   `json:"targetID,omitempty"`
	IdentitySystem  string   `json:"identitySystem,omitempty"`
	DuplicateCopies int      `json:"duplicateCopies,omitempty"`
}

// FrameworkChange is one framework's classification for a unique finding.
type FrameworkChange struct {
	ControlChange
	Framework string `json:"framework"`
	Category  string `json:"category"`
}

// CoverageChange explains why missing coverage must not be counted as a
// resolution or a new failure.
type CoverageChange struct {
	Category   string   `json:"category"`
	Side       string   `json:"side,omitempty"`
	Framework  string   `json:"framework,omitempty"`
	TargetID   string   `json:"targetID,omitempty"`
	ResourceID string   `json:"resourceID,omitempty"`
	ControlID  string   `json:"controlID,omitempty"`
	Reason     string   `json:"reason"`
	SourceIDs  []string `json:"sourceIDs,omitempty"`
}

// ConflictSource preserves the two sides of a contradictory same-evidence
// conclusion. It contains status/provenance only, never raw exception bodies.
type ConflictSource struct {
	SourceID    string `json:"sourceID"`
	Framework   string `json:"framework,omitempty"`
	Status      string `json:"status"`
	SubStatus   string `json:"subStatus,omitempty"`
	Severity    string `json:"severity,omitempty"`
	ControlName string `json:"controlName,omitempty"`
}

// Conflict is an irreconcilable conclusion for the same five-layer identity.
type Conflict struct {
	Category string           `json:"category"`
	Side     string           `json:"side,omitempty"`
	Identity Identity         `json:"identity"`
	Reason   string           `json:"reason"`
	Sources  []ConflictSource `json:"sources"`
}

// IdentityMismatch records identifiers that cannot safely be compared.
type IdentityMismatch struct {
	Category  string    `json:"category"`
	Layer     string    `json:"layer"`
	Reason    string    `json:"reason"`
	Left      *Identity `json:"left,omitempty"`
	Right     *Identity `json:"right,omitempty"`
	SourceIDs []string  `json:"sourceIDs,omitempty"`
}

// MetadataAdjustment is the audit trail for deterministic normalization when
// the same control has different severity or weight in grouped reports.
type MetadataAdjustment struct {
	Category  string   `json:"category"`
	ControlID string   `json:"controlID"`
	Field     string   `json:"field"`
	Values    []string `json:"values"`
	Selected  string   `json:"selected"`
	Rule      string   `json:"rule"`
}

// DuplicateReport records byte-identical inputs that were merged once.
type DuplicateReport struct {
	Category string `json:"category"`
	SourceID string `json:"sourceID"`
	Copies   int    `json:"copies"`
	Reason   string `json:"reason"`
}

// MultiCounts contains counts derived from the normalized multi-report state.
type MultiCounts struct {
	New                int `json:"new"`
	Resolved           int `json:"resolved"`
	Unchanged          int `json:"unchanged"`
	Incomparable       int `json:"incomparable"`
	FrameworkNew       int `json:"frameworkNew"`
	FrameworkResolved  int `json:"frameworkResolved"`
	FrameworkUnchanged int `json:"frameworkUnchanged"`
	FrameworkOther     int `json:"frameworkIncomparable"`
	CoverageChanges    int `json:"coverageChanges"`
	Conflicts          int `json:"conflicts"`
	IdentityMismatches int `json:"identityMismatches"`
	DuplicateReports   int `json:"duplicateReports"`
	UniqueFindings     int `json:"uniqueFindings"`
	GateFailures       int `json:"gateFailures"`
}

// MultiChangeSet is the framework-aware comparison result. Its embedded
// ChangeSet keeps aggregate fields compatible with existing JSON consumers.
type MultiChangeSet struct {
	ChangeSet
	SchemaVersion       string               `json:"schemaVersion"`
	Counts              MultiCounts          `json:"counts"`
	FrameworkChanges    []FrameworkChange    `json:"frameworkChanges,omitempty"`
	CoverageChanges     []CoverageChange     `json:"coverageChanges,omitempty"`
	Conflicts           []Conflict           `json:"conflicts,omitempty"`
	IdentityMismatches  []IdentityMismatch   `json:"identityMismatches,omitempty"`
	MetadataAdjustments []MetadataAdjustment `json:"metadataAdjustments,omitempty"`
	DuplicateReports    []DuplicateReport    `json:"duplicateReports,omitempty"`
	Sources             []Source             `json:"sources,omitempty"`
}

const multiSchemaVersion = "kubescape.diff.reportset/v1"

// GateFailureCount returns unique fail-closed items at or above threshold.
// Conflicts and identity mismatches are always gate failures; aggregate
// findings are counted once by identity rather than once per framework.
func (m *MultiChangeSet) GateFailureCount(threshold string) int {
	if m == nil {
		return 0
	}
	keys := make(map[string]struct{})
	for _, change := range FilterBySeverity(m.New, threshold) {
		keys[identityFromChange(change).cacheKey()] = struct{}{}
	}
	for _, change := range FilterBySeverity(m.Incomparable, threshold) {
		keys[identityFromChange(change).cacheKey()] = struct{}{}
	}
	for _, conflict := range m.Conflicts {
		keys[conflict.Identity.cacheKey()] = struct{}{}
	}
	for _, mismatch := range m.IdentityMismatches {
		data, _ := json.Marshal(mismatch)
		keys["identity-mismatch:"+string(data)] = struct{}{}
	}
	return len(keys)
}
