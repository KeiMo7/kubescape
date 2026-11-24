package diff

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fwReportJSON(t *testing.T, framework string, controlIDs []string, controls ...resultEntry) []byte {
	t.Helper()
	fwControls := map[string]controlSummary{}
	allControls := map[string]controlSummary{}
	for _, id := range controlIDs {
		fwControls[id] = controlSummary{Severity: "High"}
		allControls[id] = controlSummary{Severity: "High"}
	}
	report := scanReport{
		Results: controls,
		SummaryDetails: summaryDetails{
			Controls: allControls,
			Frameworks: []frameworkSummary{{
				Name:     framework,
				Controls: fwControls,
			}},
		},
	}
	data, err := json.Marshal(report)
	require.NoError(t, err)
	return data
}

func failedRuleResult(resourceID, controlID, ruleName string) resultEntry {
	return makeResult(resourceID, controlEntry{
		ControlID: controlID,
		Name:      controlID + "-name",
		Status:    statusInfo{InnerStatus: "failed"},
		Rules: []ruleEntry{{
			Name:   ruleName,
			Status: "failed",
		}},
	})
}

func passedRuleResult(resourceID, controlID, ruleName string) resultEntry {
	return makeResult(resourceID, controlEntry{
		ControlID: controlID,
		Name:      controlID + "-name",
		Status:    statusInfo{InnerStatus: "passed"},
		Rules: []ruleEntry{{
			Name:   ruleName,
			Status: "passed",
		}},
	})
}

func TestMultiReport_ThreeFrameworksUniqueAggregateCounts(t *testing.T) {
	const resource = "apps/v1/default/Deployment/api"
	base := [][]byte{
		fwReportJSON(t, "FW-A", []string{"C1", "C2"}, failedRuleResult(resource, "C1", "R1"), failedRuleResult(resource, "C2", "R2")),
		fwReportJSON(t, "FW-B", []string{"C1", "C3"}, failedRuleResult(resource, "C1", "R1"), failedRuleResult(resource, "C3", "R3")),
		fwReportJSON(t, "FW-C", []string{"C3", "C4"}, failedRuleResult(resource, "C3", "R3"), passedRuleResult(resource, "C4", "R4")),
	}
	head := [][]byte{
		fwReportJSON(t, "FW-A", []string{"C1", "C2"}, failedRuleResult(resource, "C1", "R1"), passedRuleResult(resource, "C2", "R2")),
		fwReportJSON(t, "FW-B", []string{"C1", "C3"}, failedRuleResult(resource, "C1", "R1"), failedRuleResult(resource, "C3", "R3")),
		fwReportJSON(t, "FW-C", []string{"C3", "C4"}, failedRuleResult(resource, "C3", "R3"), failedRuleResult(resource, "C4", "R4")),
	}

	m, err := CompareReportSetBytes(base, head, Options{Granularity: GranularityEvidence})
	require.NoError(t, err)

	assert.Len(t, m.New, 1, "C4 must be one aggregate new finding")
	assert.Len(t, m.Resolved, 1, "C2 must be one aggregate resolved finding")
	assert.Len(t, m.Unchanged, 2, "C1 and C3 shared evidence remain unchanged once each")
	assert.Empty(t, m.Incomparable)
	assert.Equal(t, 1, m.Counts.New)
	assert.Equal(t, 1, m.Counts.Resolved)
	assert.Equal(t, 2, m.Counts.Unchanged)

	frameworksByControl := map[string]map[string]bool{}
	for _, fc := range m.FrameworkChanges {
		if frameworksByControl[fc.ControlID] == nil {
			frameworksByControl[fc.ControlID] = map[string]bool{}
		}
		frameworksByControl[fc.ControlID][fc.Framework] = true
	}
	assert.Equal(t, map[string]bool{"FW-A": true, "FW-B": true}, frameworksByControl["C1"])
	assert.Equal(t, map[string]bool{"FW-B": true, "FW-C": true}, frameworksByControl["C3"])
	assert.Equal(t, map[string]bool{"FW-A": true}, frameworksByControl["C2"])
	assert.Equal(t, map[string]bool{"FW-C": true}, frameworksByControl["C4"])
}

func exceptionReportJSON(t *testing.T, framework, resource, controlID string, exceptionFramework string) []byte {
	t.Helper()
	policy := ""
	if exceptionFramework != "" {
		policy = fmt.Sprintf(`,"exception":[{"actions":["disable"],"reason":"secret-exception-marker","createdBy":"security-team","posturePolicies":[{"frameworkName":%q,"controlID":%q,"ruleName":"R1"}]}]`, exceptionFramework, controlID)
	}
	data := []byte(fmt.Sprintf(`{"results":[{"resourceID":%q,"controls":[{"controlID":%q,"name":"Shared","status":{"status":"failed"},"rules":[{"name":"R1","status":"failed"%s}]}]}],"summaryDetails":{"controls":{%q:{"severity":"High"}},"frameworks":[{"name":%q,"controls":{%q:{}}}]}}`,
		resource, controlID, policy, controlID, framework, controlID))
	_, err := parseReport(data)
	require.NoError(t, err)
	return data
}

func TestMultiReport_FrameworkSpecificExceptionDoesNotLeak(t *testing.T) {
	const resource = "apps/v1/default/Deployment/api"
	base := [][]byte{
		fwReportJSON(t, "NSA", []string{"C1"}, failedRuleResult(resource, "C1", "R1")),
		fwReportJSON(t, "MITRE", []string{"C1"}, failedRuleResult(resource, "C1", "R1")),
	}
	head := [][]byte{
		exceptionReportJSON(t, "NSA", resource, "C1", "NSA"),
		exceptionReportJSON(t, "MITRE", resource, "C1", "NSA"),
	}

	m, err := CompareReportSetBytes(base, head, Options{Granularity: GranularityEvidence})
	require.NoError(t, err)
	assert.Len(t, m.Unchanged, 1, "aggregate evidence remains failed through MITRE and is counted once")
	assert.Empty(t, m.New)
	assert.Empty(t, m.Resolved, "aggregate must not be resolved while any framework fails")

	categories := map[string]string{}
	for _, fc := range m.FrameworkChanges {
		categories[fc.Framework] = fc.Category
	}
	assert.Equal(t, CategoryFrameworkResolved, categories["NSA"])
	assert.Equal(t, CategoryFrameworkUnchanged, categories["MITRE"])

	mergedBase, err := MergeReportSetBytes(base)
	require.NoError(t, err)
	mergedHead, err := MergeReportSetBytes(head)
	require.NoError(t, err)
	assert.NotContains(t, string(mergedHead), "secret-exception-marker")
	assert.NotContains(t, string(mergedHead), "security-team")
	roundTrip, err := CompareReportSetBytes([][]byte{mergedBase}, [][]byte{mergedHead}, Options{})
	require.NoError(t, err)
	rtCategories := map[string]string{}
	for _, fc := range roundTrip.FrameworkChanges {
		rtCategories[fc.Framework] = fc.Category
	}
	assert.Equal(t, categories, rtCategories)
}

func TestMultiReport_CoverageDifferencesAreNotRecoveries(t *testing.T) {
	const resource = "apps/v1/default/Deployment/api"

	t.Run("framework only on head", func(t *testing.T) {
		base := [][]byte{fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(resource, "C1", "R1"))}
		head := [][]byte{
			fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(resource, "C1", "R1")),
			fwReportJSON(t, "FW-B", []string{"C2"}, failedRuleResult(resource, "C2", "R2")),
		}
		m, err := CompareReportSetBytes(base, head, Options{})
		require.NoError(t, err)
		assert.Empty(t, m.New)
		assert.Empty(t, m.Resolved)
		require.Len(t, m.Incomparable, 1)
		assert.Equal(t, "C2", m.Incomparable[0].ControlID)
		require.NotEmpty(t, m.CoverageChanges)
		assert.Equal(t, CategoryCoverageFrameworkSide, m.CoverageChanges[0].Category)
		assert.Contains(t, m.CoverageChanges[0].Reason, "FW-B")
	})

	t.Run("control out of scope on head", func(t *testing.T) {
		base := [][]byte{fwReportJSON(t, "FW-A", []string{"C1", "C2"},
			failedRuleResult(resource, "C1", "R1"), failedRuleResult(resource, "C2", "R2"))}
		head := [][]byte{fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(resource, "C1", "R1"))}
		m, err := CompareReportSetBytes(base, head, Options{})
		require.NoError(t, err)
		assert.Empty(t, m.Resolved)
		require.Len(t, m.Incomparable, 1)
		assert.Equal(t, "C2", m.Incomparable[0].ControlID)
		require.Len(t, filterCoverageCategory(m.CoverageChanges, CategoryCoverageControlScope), 1)
	})

	t.Run("evaluation incomplete on head", func(t *testing.T) {
		incomplete := makeResult(resource, controlEntry{
			ControlID: "C2",
			Name:      "C2-name",
			Status:    statusInfo{InnerStatus: "passed", SubStatus: "notEvaluated"},
			Rules:     []ruleEntry{{Name: "R2", Status: "passed", SubStatus: "notEvaluated"}},
		})
		base := [][]byte{fwReportJSON(t, "FW-A", []string{"C2"}, failedRuleResult(resource, "C2", "R2"))}
		head := [][]byte{fwReportJSON(t, "FW-A", []string{"C2"}, incomplete)}
		m, err := CompareReportSetBytes(base, head, Options{})
		require.NoError(t, err)
		assert.Empty(t, m.Resolved)
		require.Len(t, m.Incomparable, 1)
		items := filterCoverageCategory(m.CoverageChanges, CategoryCoverageIncomplete)
		require.Len(t, items, 1)
		assert.Contains(t, items[0].Reason, "not evaluated")
	})
}

func filterCoverageCategory(items []CoverageChange, category string) []CoverageChange {
	var result []CoverageChange
	for _, item := range items {
		if item.Category == category {
			result = append(result, item)
		}
	}
	return result
}

func TestMultiReport_ConflictSourcesGateAndNoExceptionLeak(t *testing.T) {
	const resource = "apps/v1/default/Deployment/api"
	conflictingPass := passedRuleResult(resource, "C1", "R1")
	base := [][]byte{
		fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(resource, "C1", "R1")),
		fwReportJSON(t, "FW-A", []string{"C1"}, conflictingPass),
	}
	head := [][]byte{fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(resource, "C1", "R1"))}
	m, err := CompareReportSetBytes(base, head, Options{})
	require.NoError(t, err)
	require.Len(t, m.Conflicts, 1)
	assert.Equal(t, CategoryConflictEvidence, m.Conflicts[0].Category)
	assert.Len(t, m.Conflicts[0].Sources, 2)
	assert.Contains(t, m.Conflicts[0].Reason, "contradictory")
	assert.Greater(t, m.GateFailureCount(""), 0)

	var buf strings.Builder
	require.NoError(t, PrintMultiJSON(&buf, m))
	data := []byte(buf.String())
	assert.NotContains(t, string(data), "secret-exception-policy")
}

func TestMultiReport_MergeRoundTripIsSemanticallyIdenticalAndDeterministic(t *testing.T) {
	const resource = "apps/v1/default/Deployment/api"
	base := [][]byte{
		fwReportJSON(t, "FW-A", []string{"C1", "C2"}, failedRuleResult(resource, "C1", "R1"), failedRuleResult(resource, "C2", "R2")),
		fwReportJSON(t, "FW-B", []string{"C1", "C3"}, failedRuleResult(resource, "C1", "R1"), failedRuleResult(resource, "C3", "R3")),
		fwReportJSON(t, "FW-C", []string{"C3", "C4"}, failedRuleResult(resource, "C3", "R3"), passedRuleResult(resource, "C4", "R4")),
	}
	head := [][]byte{
		fwReportJSON(t, "FW-A", []string{"C1", "C2"}, failedRuleResult(resource, "C1", "R1"), passedRuleResult(resource, "C2", "R2")),
		fwReportJSON(t, "FW-B", []string{"C1", "C3"}, failedRuleResult(resource, "C1", "R1"), failedRuleResult(resource, "C3", "R3")),
		fwReportJSON(t, "FW-C", []string{"C3", "C4"}, failedRuleResult(resource, "C3", "R3"), failedRuleResult(resource, "C4", "R4")),
	}
	direct, err := CompareReportSetBytes(base, head, Options{})
	require.NoError(t, err)

	mergedBase, err := MergeReportSetBytes(base)
	require.NoError(t, err)
	mergedBaseAgain, err := MergeReportSetBytes(base)
	require.NoError(t, err)
	assert.Equal(t, mergedBase, mergedBaseAgain, "merged report bytes must be deterministic")
	_, err = parseReport(mergedBase)
	require.NoError(t, err, "merged report must remain a valid existing posture report")

	mergedHead, err := MergeReportSetBytes(head)
	require.NoError(t, err)
	roundTrip, err := CompareReportSetBytes([][]byte{mergedBase}, [][]byte{mergedHead}, Options{})
	require.NoError(t, err)
	assert.Equal(t, direct, roundTrip)

	assert.Equal(t, direct.Counts.New, roundTrip.Counts.New)
	assert.Equal(t, direct.Counts.Resolved, roundTrip.Counts.Resolved)
	assert.Equal(t, direct.Counts.Unchanged, roundTrip.Counts.Unchanged)
	assert.Equal(t, direct.Counts.Incomparable, roundTrip.Counts.Incomparable)
	assert.Len(t, roundTrip.New, len(direct.New))
	assert.Len(t, roundTrip.Resolved, len(direct.Resolved))
	assert.Len(t, roundTrip.Unchanged, len(direct.Unchanged))
	assert.Equal(t, frameworkCategories(direct), frameworkCategories(roundTrip))

	directJSON, err := json.Marshal(direct)
	require.NoError(t, err)
	again, err := CompareReportSetBytes(base, head, Options{})
	require.NoError(t, err)
	againJSON, err := json.Marshal(again)
	require.NoError(t, err)
	assert.JSONEq(t, string(directJSON), string(againJSON), "two comparisons must serialize identically")
}

func frameworkCategories(m *MultiChangeSet) map[string]string {
	result := map[string]string{}
	for _, fc := range m.FrameworkChanges {
		result[fc.Framework+"|"+fc.ControlID+"|"+fc.RuleName] = fc.Category
	}
	return result
}

func TestMultiReport_SameFrameworkCanBeSplitAcrossReports(t *testing.T) {
	const resource = "apps/v1/default/Deployment/split"
	base := [][]byte{
		fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(resource, "C1", "R1")),
		fwReportJSON(t, "FW-A", []string{"C2"}, failedRuleResult(resource, "C2", "R2")),
	}
	head := [][]byte{
		fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(resource, "C1", "R1")),
		fwReportJSON(t, "FW-A", []string{"C2"}, passedRuleResult(resource, "C2", "R2")),
	}
	m, err := CompareReportSetBytes(base, head, Options{})
	require.NoError(t, err)
	assert.Len(t, m.Unchanged, 1)
	assert.Len(t, m.Resolved, 1)
	require.Len(t, m.FrameworkChanges, 2)
	for _, fc := range m.FrameworkChanges {
		assert.Equal(t, "FW-A", fc.Framework)
	}
}

func TestMultiReport_AnonymousAndClearTextIdentitySystemsAreNotMerged(t *testing.T) {
	const clearResource = "apps/v1/default/Deployment/checkout"
	const pseudoResource = "res-0123456789abcdef0123456789abcdef"
	base := [][]byte{
		fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(clearResource, "C1", "R1")),
		fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(pseudoResource, "C1", "R1")),
	}
	head := [][]byte{fwReportJSON(t, "FW-A", []string{"C1"}, failedRuleResult(clearResource, "C1", "R1"))}
	m, err := CompareReportSetBytes(base, head, Options{})
	require.NoError(t, err)
	require.Len(t, m.IdentityMismatches, 1)
	assert.Equal(t, "identitySystem", m.IdentityMismatches[0].Layer)
	assert.NotEmpty(t, m.IdentityMismatches[0].SourceIDs)
	assert.Empty(t, m.New)
	assert.Empty(t, m.Resolved)
	assert.Greater(t, m.GateFailureCount(""), 0)

	data, err := json.Marshal(m)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"identitySystem":"anonymized"`)
	assert.NotContains(t, string(data), "original-secret-exception")
}

func TestMultiReport_TenReportsDoNotDuplicateAggregateEvidence(t *testing.T) {
	const resource = "apps/v1/default/Deployment/ten"
	var base, head [][]byte
	for i := 0; i < 10; i++ {
		fw := fmt.Sprintf("FW-%02d", i)
		base = append(base, fwReportJSON(t, fw, []string{"C1"}, failedRuleResult(resource, "C1", "R1")))
		head = append(head, fwReportJSON(t, fw, []string{"C1"}, failedRuleResult(resource, "C1", "R1")))
	}
	m, err := CompareReportSetBytes(base, head, Options{})
	require.NoError(t, err)
	assert.Len(t, m.Unchanged, 1)
	assert.Len(t, m.FrameworkChanges, 10)
	assert.Empty(t, m.New)
	assert.Empty(t, m.Resolved)
	assert.Empty(t, m.Incomparable)
	refs := map[string]struct{}{}
	for _, fc := range m.FrameworkChanges {
		refs[fc.EvidenceRef] = struct{}{}
	}
	assert.Len(t, refs, 1, "same evidence pointer must be shared across frameworks")
}
