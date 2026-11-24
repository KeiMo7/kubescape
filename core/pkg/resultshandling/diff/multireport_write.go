package diff

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/armosec/armoapi-go/armotypes"
)

// MergeReportSetFiles loads, validates, deduplicates and deterministically
// merges a group of posture reports into one report-shaped JSON document.
func MergeReportSetFiles(paths []string) ([]byte, error) {
	set, err := loadReportSet(paths, "merge")
	if err != nil {
		return nil, err
	}
	return marshalMergedSet(set)
}

// MergeReportSetBytes is the in-memory form of MergeReportSetFiles.
func MergeReportSetBytes(items [][]byte) ([]byte, error) {
	set, err := buildReportSet(items)
	if err != nil {
		return nil, err
	}
	return marshalMergedSet(set)
}

func marshalMergedSet(set *reportSet) ([]byte, error) {
	report := mergeLoadedReportsForStorage(set)
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding merged report: %w", err)
	}
	return append(data, '\n'), nil
}

// WriteMergedReportSet merges paths and writes the canonical JSON document.
func WriteMergedReportSet(paths []string, outputPath string) error {
	data, err := MergeReportSetFiles(paths)
	if err != nil {
		return err
	}
	if err := os.WriteFile(outputPath, data, 0o600); err != nil {
		return fmt.Errorf("writing merged report %q: %w", outputPath, err)
	}
	return nil
}

func mergeLoadedReportsForStorage(set *reportSet) *scanReport {
	merged := &scanReport{
		SummaryDetails: summaryDetails{Controls: map[string]controlSummary{}},
	}
	controlMap := map[string]map[string]*controlEntry{}
	resourceSeen := map[string]struct{}{}
	frameworks := map[string]*frameworkSummary{}
	var adjustments []MetadataAdjustment
	var conflicts []Conflict

	for _, loaded := range set.reports {
		report := loaded.report
		mergeMetadataInto(merged, report)
		mergeCoverageInto(&merged.ScanCoverage, report.ScanCoverage)
		for id, summary := range report.SummaryDetails.Controls {
			current := merged.SummaryDetails.Controls[id]
			chosen, adjustment := mergeControlSummary(id, current, summary)
			merged.SummaryDetails.Controls[id] = chosen
			adjustments = append(adjustments, adjustment...)
		}
		for _, fw := range report.SummaryDetails.Frameworks {
			name := fw.Name
			if name == "" {
				continue
			}
			current := frameworks[name]
			if current == nil {
				copyFW := frameworkSummary{Name: name, Controls: map[string]controlSummary{}}
				frameworks[name] = &copyFW
				current = frameworks[name]
			}
			for id, control := range fw.Controls {
				if _, exists := current.Controls[id]; !exists {
					current.Controls[id] = control
				}
			}
		}

		for _, result := range report.Results {
			if _, exists := controlMap[result.ResourceID]; !exists {
				controlMap[result.ResourceID] = map[string]*controlEntry{}
				resourceSeen[result.ResourceID] = struct{}{}
			}
			for _, control := range result.AssociatedControls {
				sanitizeExceptionPoliciesForMerge(&control)
				current := controlMap[result.ResourceID][control.ControlID]
				if current == nil {
					copied := mergeControlCopies(control)
					controlMap[result.ResourceID][control.ControlID] = &copied
					continue
				}
				mergeControlInto(current, control)
			}
		}
	}

	resourceIDs := make([]string, 0, len(resourceSeen))
	for id := range resourceSeen {
		resourceIDs = append(resourceIDs, id)
	}
	sort.Strings(resourceIDs)
	for _, resourceID := range resourceIDs {
		result := resultEntry{ResourceID: resourceID}
		controlIDs := make([]string, 0, len(controlMap[resourceID]))
		for id := range controlMap[resourceID] {
			controlIDs = append(controlIDs, id)
		}
		sort.Strings(controlIDs)
		for _, id := range controlIDs {
			result.AssociatedControls = append(result.AssociatedControls, *controlMap[resourceID][id])
		}
		merged.Results = append(merged.Results, result)
	}

	names := make([]string, 0, len(frameworks))
	for name := range frameworks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fw := frameworks[name]
		merged.SummaryDetails.Frameworks = append(merged.SummaryDetails.Frameworks, *fw)
	}

	// Analyze framework views so conflict provenance survives a write/read
	// round-trip in the additive manifest.
	allFrameworks := unionFrameworks(set, &reportSet{})
	for _, fw := range allFrameworks {
		view := buildFrameworkSide(set, fw, GranularityEvidence)
		for i := range view.conflicts {
			view.conflicts[i].Side = "merged"
		}
		conflicts = append(conflicts, view.conflicts...)
		adjustments = append(adjustments, view.adjustments...)
	}
	conflicts = dedupeConflicts(conflicts)
	adjustments = dedupeAdjustments(adjustments)

	merged.IdentitySystem = set.identitySystem
	score, method := deriveMergedScore(merged)
	merged.SummaryDetails.Score = score
	merged.SummaryDetails.ScoreMode = method
	merged.DiffMerge = &mergeManifest{
		Version:        multiSchemaVersion,
		SourceSHA256:   sourceHashes(set.sources),
		Sources:        append([]Source(nil), set.sources...),
		TargetID:       set.targetID,
		IdentitySystem: set.identitySystem,
		ScoreMethod:    method,
		Conflicts:      conflicts,
		Adjustments:    adjustments,
	}
	return merged
}

func sourceHashes(sources []Source) []string {
	result := make([]string, 0, len(sources))
	for _, source := range sources {
		result = append(result, source.SHA256)
	}
	sort.Strings(result)
	return result
}

// sanitizeExceptionPoliciesForMerge removes free-form exception payloads from
// the merged report. Only the action kind and the framework/control/rule tuple
// needed to reproduce framework-scoped status are retained; reasons, creators,
// resources and other original exception content never enter merged output.
func sanitizeExceptionPoliciesForMerge(control *controlEntry) {
	if control == nil {
		return
	}
	for ruleIndex := range control.Rules {
		exceptions := control.Rules[ruleIndex].Exception
		if len(exceptions) == 0 {
			continue
		}
		safe := make([]armotypes.PostureExceptionPolicy, 0, len(exceptions))
		for _, exception := range exceptions {
			redacted := armotypes.PostureExceptionPolicy{Actions: append([]armotypes.PostureExceptionPolicyActions(nil), exception.Actions...)}
			for _, policy := range exception.PosturePolicies {
				redacted.PosturePolicies = append(redacted.PosturePolicies, armotypes.PosturePolicy{
					FrameworkName: policy.FrameworkName,
					ControlID:     policy.ControlID,
					RuleName:      policy.RuleName,
				})
			}
			safe = append(safe, redacted)
		}
		control.Rules[ruleIndex].Exception = safe
	}
}

// deriveMergedScore computes a risk score from unique merged resource/control
// states. It is deliberately not a sum or arithmetic mean of input scores.
func deriveMergedScore(report *scanReport) (float64, string) {
	const method = "unique-resource-control-risk-weighted-v1"
	var failedWeight, totalWeight float64
	for _, result := range report.Results {
		for _, control := range result.AssociatedControls {
			summary := report.SummaryDetails.Controls[control.ControlID]
			weight := float64(summary.ScoreFactor)
			if weight <= 0 {
				weight = float64(severityRank(severityFromSummary(summary)))
			}
			if weight <= 0 {
				weight = 1
			}
			totalWeight += weight
			if control.Status.InnerStatus == "failed" {
				failedWeight += weight
			}
		}
	}
	if totalWeight == 0 {
		return 0, method
	}
	return roundFloat(100*failedWeight/totalWeight, 5), method
}
