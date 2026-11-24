package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
)

type aggregateEntry struct {
	change              ControlChange
	baseFailed          bool
	headFailed          bool
	hasIncomparable     bool
	conflict            bool
	baseStatuses        []string
	headStatuses        []string
	reasons             map[string]struct{}
	sourceIDs           map[string]struct{}
	frameworkCategories map[string]string
}

type aggregateIndex struct {
	entries map[string]*aggregateEntry
}

func newAggregateIndex() *aggregateIndex {
	return &aggregateIndex{entries: make(map[string]*aggregateEntry)}
}

func (a *aggregateIndex) add(fc FrameworkChange) {
	key := identityFromChange(fc.ControlChange).cacheKey()
	entry := a.entries[key]
	if entry == nil {
		entry = &aggregateEntry{
			change:              fc.ControlChange,
			reasons:             make(map[string]struct{}),
			sourceIDs:           make(map[string]struct{}),
			frameworkCategories: make(map[string]string),
		}
		a.entries[key] = entry
	}
	entry.mergeChange(fc.ControlChange)
	entry.frameworkCategories[fc.Framework] = fc.Category
	if fc.Category == CategoryFrameworkIncomparable || fc.Category == CategoryCoverageFrameworkSide {
		entry.hasIncomparable = true
	}
}

func (a *aggregateIndex) addConflict(id Identity, change ControlChange) {
	key := id.cacheKey()
	entry := a.entries[key]
	if entry == nil {
		entry = &aggregateEntry{
			change:              change,
			reasons:             make(map[string]struct{}),
			sourceIDs:           make(map[string]struct{}),
			frameworkCategories: make(map[string]string),
		}
		a.entries[key] = entry
	}
	entry.conflict = true
	entry.hasIncomparable = true
	entry.mergeChange(change)
}

func (e *aggregateEntry) mergeChange(change ControlChange) {
	if change.BaseStatus == string(apis.StatusFailed) {
		e.baseFailed = true
	}
	if change.HeadStatus == string(apis.StatusFailed) {
		e.headFailed = true
	}
	if change.BaseStatus != "" {
		e.baseStatuses = append(e.baseStatuses, change.BaseStatus)
	}
	if change.HeadStatus != "" {
		e.headStatuses = append(e.headStatuses, change.HeadStatus)
	}
	if change.Reason != "" {
		e.reasons[change.Reason] = struct{}{}
	}
	for _, id := range change.SourceIDs {
		e.sourceIDs[id] = struct{}{}
	}

	current := e.change
	if severityRank(change.Severity) > severityRank(current.Severity) || (current.Severity == "" && change.Severity != "") {
		current.Severity = change.Severity
	}
	if current.ControlName == "" {
		current.ControlName = change.ControlName
	}
	if current.TargetID == "" {
		current.TargetID = change.TargetID
	}
	if current.Reason == "" {
		current.Reason = change.Reason
	}
	e.change = current
}

func (a *aggregateIndex) resolve(targetMismatch bool, baseTarget, headTarget string) (newItems, resolved, unchanged, incomparable []ControlChange) {
	keys := make([]string, 0, len(a.entries))
	for key := range a.entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		entry := a.entries[key]
		change := entry.change
		change.BaseStatus = aggregateStatus(entry.baseStatuses, entry.baseFailed)
		change.HeadStatus = aggregateStatus(entry.headStatuses, entry.headFailed)
		reasons := make([]string, 0, len(entry.reasons))
		for reason := range entry.reasons {
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		change.Reason = strings.Join(reasons, "; ")
		ids := make([]string, 0, len(entry.sourceIDs))
		for id := range entry.sourceIDs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		change.SourceIDs = ids

		switch {
		case entry.hasIncomparable || entry.conflict || targetMismatch:
			change.Category = CategoryAggregateIncomparable
			if targetMismatch && change.TargetID == "" {
				// Keep the five-layer target coordinates visible in the reason;
				// IdentityMismatch carries the structured left/right targets.
				change.TargetID = ""
			}
			incomparable = append(incomparable, change)
		case entry.baseFailed && entry.headFailed:
			change.Category = CategoryAggregateUnchanged
			unchanged = append(unchanged, change)
		case !entry.baseFailed && entry.headFailed:
			change.Category = CategoryAggregateNew
			newItems = append(newItems, change)
		case entry.baseFailed && !entry.headFailed:
			change.Category = CategoryAggregateResolved
			resolved = append(resolved, change)
		default:
			// No failed side means no finding belongs in an aggregate diff.
			// Framework-level non-failed transitions remain in FrameworkChanges.
		}
	}
	return newItems, resolved, unchanged, incomparable
}

func aggregateStatus(statuses []string, failed bool) string {
	if failed {
		return string(apis.StatusFailed)
	}
	hasPassed := false
	for _, status := range statuses {
		switch status {
		case string(apis.StatusPassed):
			hasPassed = true
		case statusAbsent:
			// absent is useful when no stronger status exists.
		default:
			if status != "" && status != statusAbsent {
				return status
			}
		}
	}
	if hasPassed {
		return string(apis.StatusPassed)
	}
	for _, status := range statuses {
		if status != "" {
			return status
		}
	}
	return ""
}

func evidenceReference(change ControlChange) string {
	return evidenceReferenceFromIdentity(identityFromChange(change))
}

// evidenceReferenceFromIdentity hashes only the layers below control. It lets
// consumers see that findings under different controls point at the same rule
// evidence while those findings remain separately counted by control.
func evidenceReferenceFromIdentity(id Identity) string {
	id.ControlID = ""
	data, _ := json.Marshal(id)
	sum := sha256.Sum256(data)
	return "ev_" + hex.EncodeToString(sum[:])[:16]
}

func sortMulti(m *MultiChangeSet) {
	sortChangeSet(&m.ChangeSet)
	sort.Slice(m.FrameworkChanges, func(i, j int) bool {
		left, right := m.FrameworkChanges[i], m.FrameworkChanges[j]
		if left.Framework != right.Framework {
			return left.Framework < right.Framework
		}
		return compareChangeOrder(left.ControlChange, right.ControlChange)
	})
	sort.Slice(m.CoverageChanges, func(i, j int) bool {
		left, right := m.CoverageChanges[i], m.CoverageChanges[j]
		if left.Category != right.Category {
			return left.Category < right.Category
		}
		if left.Framework != right.Framework {
			return left.Framework < right.Framework
		}
		if left.ControlID != right.ControlID {
			return left.ControlID < right.ControlID
		}
		if left.ResourceID != right.ResourceID {
			return left.ResourceID < right.ResourceID
		}
		return left.Reason < right.Reason
	})
	sort.Slice(m.Conflicts, func(i, j int) bool {
		return m.Conflicts[i].Identity.cacheKey() < m.Conflicts[j].Identity.cacheKey()
	})
	sort.Slice(m.IdentityMismatches, func(i, j int) bool {
		if m.IdentityMismatches[i].Layer != m.IdentityMismatches[j].Layer {
			return m.IdentityMismatches[i].Layer < m.IdentityMismatches[j].Layer
		}
		return m.IdentityMismatches[i].Reason < m.IdentityMismatches[j].Reason
	})
}

func compareChangeOrder(left, right ControlChange) bool {
	if severityRank(left.Severity) != severityRank(right.Severity) {
		return severityRank(left.Severity) > severityRank(right.Severity)
	}
	if left.ResourceID != right.ResourceID {
		return left.ResourceID < right.ResourceID
	}
	if left.ControlID != right.ControlID {
		return left.ControlID < right.ControlID
	}
	if left.RuleName != right.RuleName {
		return left.RuleName < right.RuleName
	}
	if left.EvidenceType != right.EvidenceType {
		return left.EvidenceType < right.EvidenceType
	}
	if left.Path != right.Path {
		return left.Path < right.Path
	}
	return left.EvidenceResourceID < right.EvidenceResourceID
}

func finalizeMulti(m *MultiChangeSet) {
	m.Sources = dedupeSources(m.Sources)
	m.Warnings = compactStrings(m.Warnings)
	m.Counts = MultiCounts{
		New:                len(m.New),
		Resolved:           len(m.Resolved),
		Unchanged:          len(m.Unchanged),
		Incomparable:       len(m.Incomparable),
		FrameworkNew:       countFrameworkCategory(m.FrameworkChanges, CategoryFrameworkNew),
		FrameworkResolved:  countFrameworkCategory(m.FrameworkChanges, CategoryFrameworkResolved),
		FrameworkUnchanged: countFrameworkCategory(m.FrameworkChanges, CategoryFrameworkUnchanged),
		FrameworkOther:     countFrameworkCategory(m.FrameworkChanges, CategoryFrameworkIncomparable) + countFrameworkCategory(m.FrameworkChanges, CategoryCoverageFrameworkSide),
		CoverageChanges:    len(m.CoverageChanges),
		Conflicts:          len(m.Conflicts),
		IdentityMismatches: len(m.IdentityMismatches),
		DuplicateReports:   len(m.DuplicateReports),
		UniqueFindings:     len(m.New) + len(m.Resolved) + len(m.Unchanged) + len(m.Incomparable),
		GateFailures:       m.GateFailureCount(""),
	}
}

func countFrameworkCategory(changes []FrameworkChange, category string) int {
	count := 0
	for _, change := range changes {
		if change.Category == category {
			count++
		}
	}
	return count
}

func compactStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
