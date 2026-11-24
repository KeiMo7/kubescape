package diff

import (
	"encoding/json"
	"math"
	"sort"
	"strings"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/kubescape/opa-utils/reporthandling/apis"
)

func severityFromSummary(summary controlSummary) string {
	if strings.TrimSpace(summary.Severity) != "" {
		return strings.TrimSpace(summary.Severity)
	}
	return apis.ControlSeverityToString(summary.ScoreFactor)
}

func mergeControlSummary(controlID string, current, next controlSummary) (controlSummary, []MetadataAdjustment) {
	// The zero value is the accumulator's "not seen yet" marker, not a report
	// whose severity is the literal "Unknown". Do not leave an audit trail for
	// choosing the only observed metadata value.
	if current.Severity == "" && current.ScoreFactor == 0 {
		return next, nil
	}
	currentSeverity := severityFromSummary(current)
	nextSeverity := severityFromSummary(next)
	adjustments := make([]MetadataAdjustment, 0, 2)
	chosen := current

	currentRank := severityRank(currentSeverity)
	nextRank := severityRank(nextSeverity)
	if nextRank > currentRank || (currentSeverity == "" && nextSeverity != "") {
		chosen.Severity = next.Severity
	} else if chosen.Severity == "" {
		chosen.Severity = currentSeverity
	}
	// Weights are never summed or averaged. When they disagree, keep the
	// larger score factor, i.e. the most conservative weight.
	if next.ScoreFactor > chosen.ScoreFactor {
		chosen.ScoreFactor = next.ScoreFactor
	}

	if normalizeSeverityToken(currentSeverity) != normalizeSeverityToken(nextSeverity) && currentSeverity != "" && nextSeverity != "" {
		values := compactStrings([]string{currentSeverity, nextSeverity})
		adjustments = append(adjustments, MetadataAdjustment{
			Category:  CategoryMetadataAdjustment,
			ControlID: controlID,
			Field:     "severity",
			Values:    values,
			Selected:  severityFromSummary(chosen),
			Rule:      "selected the highest known severity; unknown severities are retained and fail closed",
		})
	}
	if !almostEqualFloat32(current.ScoreFactor, next.ScoreFactor) && current.ScoreFactor != 0 && next.ScoreFactor != 0 {
		values := compactStrings([]string{formatFloat32(current.ScoreFactor), formatFloat32(next.ScoreFactor)})
		adjustments = append(adjustments, MetadataAdjustment{
			Category:  CategoryMetadataAdjustment,
			ControlID: controlID,
			Field:     "scoreFactor",
			Values:    values,
			Selected:  formatFloat32(chosen.ScoreFactor),
			Rule:      "selected the maximum weight; weights are not summed or averaged",
		})
	}
	return chosen, adjustments
}

func normalizeSeverityToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func almostEqualFloat32(a, b float32) bool {
	return math.Abs(float64(a-b)) < 0.000001
}

func formatFloat32(value float32) string {
	return strings.TrimRight(strings.TrimRight(formatFloat(float64(value), 6), "0"), ".")
}

func formatFloat(value float64, precision int) string {
	// strconv is already a dependency indirectly, but keep this helper isolated.
	return jsonNumber(value, precision)
}

func jsonNumber(value float64, precision int) string {
	data, _ := json.Marshal(roundFloat(value, precision))
	return string(data)
}

func roundFloat(value float64, precision int) float64 {
	pow := math.Pow10(precision)
	return math.Round(value*pow) / pow
}

func mergeMetadataInto(dst *scanReport, src *scanReport) {
	if dst.ClusterName == "" {
		dst.ClusterName = src.ClusterName
	}
	if dst.IdentitySystem == "" {
		dst.IdentitySystem = src.IdentitySystem
	}
	srcTM := src.Metadata.TargetMetadata
	dstTM := &dst.Metadata.TargetMetadata
	if dstTM.TargetID == "" {
		dstTM.TargetID = srcTM.TargetID
	}
	if dstTM.Cluster == nil && srcTM.Cluster != nil {
		cluster := *srcTM.Cluster
		dstTM.Cluster = &cluster
	} else if dstTM.Cluster != nil && srcTM.Cluster != nil && dstTM.Cluster.ContextName == "" {
		dstTM.Cluster.ContextName = srcTM.Cluster.ContextName
	}
	if dstTM.Repo == nil && srcTM.Repo != nil {
		repo := *srcTM.Repo
		dstTM.Repo = &repo
	}

	dstScan := &dst.Metadata.ScanMetadata
	srcScan := src.Metadata.ScanMetadata
	if dstScan.TargetType == "" {
		dstScan.TargetType = srcScan.TargetType
	}
	if dstScan.ScanningTarget == nil && srcScan.ScanningTarget != nil {
		v := *srcScan.ScanningTarget
		dstScan.ScanningTarget = &v
	}
	if len(dstScan.IncludeNamespaces) == 0 {
		dstScan.IncludeNamespaces = append([]string(nil), srcScan.IncludeNamespaces...)
	} else {
		dstScan.IncludeNamespaces = compactStrings(append(dstScan.IncludeNamespaces, srcScan.IncludeNamespaces...))
	}
	if len(dstScan.ExcludedNamespaces) == 0 {
		dstScan.ExcludedNamespaces = append([]string(nil), srcScan.ExcludedNamespaces...)
	} else {
		dstScan.ExcludedNamespaces = compactStrings(append(dstScan.ExcludedNamespaces, srcScan.ExcludedNamespaces...))
	}
	if len(dstScan.TargetNames) == 0 {
		dstScan.TargetNames = append([]string(nil), srcScan.TargetNames...)
	} else {
		dstScan.TargetNames = compactStrings(append(dstScan.TargetNames, srcScan.TargetNames...))
	}
}

func mergeCoverageInto(dst *scanCoverage, src scanCoverage) {
	dst.Degraded = dst.Degraded || src.Degraded
	dst.NotEvaluatedControls = mergeNotEvaluatedControls(dst.NotEvaluatedControls, src.NotEvaluatedControls)
	dst.FailedGVRPulls = mergeFailedGVRPulls(dst.FailedGVRPulls, src.FailedGVRPulls)
	dst.PartialGVRPulls = mergeRawMessages(dst.PartialGVRPulls, src.PartialGVRPulls)
	dst.PolicyDegradations = mergeRawMessages(dst.PolicyDegradations, src.PolicyDegradations)
	dst.SkippedManifests = mergeRawMessages(dst.SkippedManifests, src.SkippedManifests)
}

func mergeNotEvaluatedControls(a, b []notEvaluatedControl) []notEvaluatedControl {
	seen := map[string]struct{}{}
	result := make([]notEvaluatedControl, 0, len(a)+len(b))
	for _, item := range append(append([]notEvaluatedControl{}, a...), b...) {
		key := item.ControlID + "\x00" + item.Reason
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ControlID != result[j].ControlID {
			return result[i].ControlID < result[j].ControlID
		}
		return result[i].Reason < result[j].Reason
	})
	return result
}

func mergeFailedGVRPulls(a, b []failedGVRPull) []failedGVRPull {
	byGVR := map[string]failedGVRPull{}
	for _, item := range append(append([]failedGVRPull{}, a...), b...) {
		current := byGVR[item.GVR]
		current.GVR = item.GVR
		current.Controls = compactStrings(append(current.Controls, item.Controls...))
		byGVR[item.GVR] = current
	}
	result := make([]failedGVRPull, 0, len(byGVR))
	for _, item := range byGVR {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].GVR < result[j].GVR })
	return result
}

func mergeRawMessages(a, b []json.RawMessage) []json.RawMessage {
	seen := map[string]struct{}{}
	result := make([]json.RawMessage, 0, len(a)+len(b))
	for _, raw := range append(append([]json.RawMessage{}, a...), b...) {
		key := string(raw)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, append(json.RawMessage(nil), raw...))
	}
	sort.Slice(result, func(i, j int) bool { return string(result[i]) < string(result[j]) })
	return result
}

func mergeControlCopies(src controlEntry) controlEntry {
	out := src
	out.Rules = append([]ruleEntry(nil), src.Rules...)
	for i := range out.Rules {
		out.Rules[i].Paths = append([]evidencePath(nil), src.Rules[i].Paths...)
		out.Rules[i].RelatedResourcesIDs = append([]string(nil), src.Rules[i].RelatedResourcesIDs...)
		out.Rules[i].Exception = append([]armotypes.PostureExceptionPolicy(nil), src.Rules[i].Exception...)
	}
	return out
}

func mergeControlInto(dst *controlEntry, src controlEntry) {
	if dst.Name == "" {
		dst.Name = src.Name
	}
	dst.Status = moreConservativeStatus(dst.Status, src.Status)
	if len(src.FrameworkNames) > 0 {
		dst.FrameworkNames = compactStrings(append(dst.FrameworkNames, src.FrameworkNames...))
	}

	for _, srcRule := range src.Rules {
		index := -1
		for i := range dst.Rules {
			if dst.Rules[i].Name == srcRule.Name {
				index = i
				break
			}
		}
		if index < 0 {
			dst.Rules = append(dst.Rules, cloneRule(srcRule))
			continue
		}
		mergeRuleInto(&dst.Rules[index], srcRule)
	}
	sort.SliceStable(dst.Rules, func(i, j int) bool { return dst.Rules[i].Name < dst.Rules[j].Name })
}

func cloneRule(rule ruleEntry) ruleEntry {
	out := rule
	out.Paths = append([]evidencePath(nil), rule.Paths...)
	out.RelatedResourcesIDs = append([]string(nil), rule.RelatedResourcesIDs...)
	out.Exception = append([]armotypes.PostureExceptionPolicy(nil), rule.Exception...)
	if rule.ControlConfigurations != nil {
		out.ControlConfigurations = make(map[string][]string, len(rule.ControlConfigurations))
		for key, values := range rule.ControlConfigurations {
			out.ControlConfigurations[key] = append([]string(nil), values...)
		}
	}
	return out
}

func mergeRuleInto(dst *ruleEntry, src ruleEntry) {
	dst.Status, dst.SubStatus = moreConservativeRuleStatus(dst.Status, dst.SubStatus, src.Status, src.SubStatus)
	dst.Paths = mergeEvidencePaths(dst.Paths, src.Paths)
	dst.RelatedResourcesIDs = compactStrings(append(dst.RelatedResourcesIDs, src.RelatedResourcesIDs...))
	dst.Exception = mergeExceptions(dst.Exception, src.Exception)
	if dst.ControlConfigurations == nil && src.ControlConfigurations != nil {
		dst.ControlConfigurations = make(map[string][]string)
	}
	for key, values := range src.ControlConfigurations {
		dst.ControlConfigurations[key] = compactStrings(append(dst.ControlConfigurations[key], values...))
	}
}

func mergeEvidencePaths(a, b []evidencePath) []evidencePath {
	seen := map[string]struct{}{}
	result := make([]evidencePath, 0, len(a)+len(b))
	for _, path := range append(append([]evidencePath{}, a...), b...) {
		data, _ := json.Marshal(path)
		key := string(data)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, path)
	}
	sort.Slice(result, func(i, j int) bool {
		left, _ := json.Marshal(result[i])
		right, _ := json.Marshal(result[j])
		return string(left) < string(right)
	})
	return result
}

func mergeExceptions(a, b []armotypes.PostureExceptionPolicy) []armotypes.PostureExceptionPolicy {
	seen := map[string]struct{}{}
	result := make([]armotypes.PostureExceptionPolicy, 0, len(a)+len(b))
	for _, exception := range append(append([]armotypes.PostureExceptionPolicy{}, a...), b...) {
		data, err := json.Marshal(exception)
		if err != nil {
			continue
		}
		key := string(data)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, exception)
	}
	return result
}

func moreConservativeStatus(a, b statusInfo) statusInfo {
	if statusConservatism(b.InnerStatus, b.SubStatus) > statusConservatism(a.InnerStatus, a.SubStatus) {
		return b
	}
	return a
}

func moreConservativeRuleStatus(aStatus, aSub, bStatus, bSub string) (string, string) {
	if statusConservatism(bStatus, bSub) > statusConservatism(aStatus, aSub) {
		return bStatus, bSub
	}
	return aStatus, aSub
}

func statusConservatism(status, subStatus string) int {
	if subStatus == string(apis.SubStatusNotEvaluated) {
		return 4
	}
	switch status {
	case string(apis.StatusFailed):
		return 5
	case string(apis.StatusSkipped):
		return 3
	case string(apis.StatusPassed):
		switch apis.ScanningSubStatus(subStatus) {
		case apis.SubStatusRequiresReview, apis.SubStatusManualReview:
			return 2
		default:
			return 1
		}
	default:
		return 0
	}
}

func dedupeConflicts(items []Conflict) []Conflict {
	byKey := map[string]*Conflict{}
	order := make([]string, 0)
	for _, item := range items {
		key := item.Side + "|" + item.Identity.cacheKey()
		current, ok := byKey[key]
		if !ok {
			copy := item
			copy.Sources = dedupeConflictSources(item.Sources)
			byKey[key] = &copy
			order = append(order, key)
			continue
		}
		current.Sources = dedupeConflictSources(append(current.Sources, item.Sources...))
		if current.Reason == "" {
			current.Reason = item.Reason
		}
	}
	result := make([]Conflict, 0, len(order))
	for _, key := range order {
		result = append(result, *byKey[key])
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Side != result[j].Side {
			return result[i].Side < result[j].Side
		}
		return result[i].Identity.cacheKey() < result[j].Identity.cacheKey()
	})
	return result
}

func dedupeConflictSources(items []ConflictSource) []ConflictSource {
	seen := map[string]struct{}{}
	result := make([]ConflictSource, 0, len(items))
	for _, item := range items {
		key := item.SourceID + "|" + item.Status + "|" + item.SubStatus
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SourceID < result[j].SourceID })
	return result
}

func dedupeCoverage(items []CoverageChange) []CoverageChange {
	seen := map[string]struct{}{}
	result := make([]CoverageChange, 0, len(items))
	for _, item := range items {
		key, _ := json.Marshal(item)
		if _, ok := seen[string(key)]; ok {
			continue
		}
		seen[string(key)] = struct{}{}
		result = append(result, item)
	}
	return result
}

func dedupeIdentityMismatches(items []IdentityMismatch) []IdentityMismatch {
	seen := map[string]struct{}{}
	result := make([]IdentityMismatch, 0, len(items))
	for _, item := range items {
		key, _ := json.Marshal(item)
		if _, ok := seen[string(key)]; ok {
			continue
		}
		seen[string(key)] = struct{}{}
		result = append(result, item)
	}
	return result
}

func dedupeAdjustments(items []MetadataAdjustment) []MetadataAdjustment {
	seen := map[string]struct{}{}
	result := make([]MetadataAdjustment, 0, len(items))
	for _, item := range items {
		key, _ := json.Marshal(item)
		if _, ok := seen[string(key)]; ok {
			continue
		}
		seen[string(key)] = struct{}{}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ControlID != result[j].ControlID {
			return result[i].ControlID < result[j].ControlID
		}
		return result[i].Field < result[j].Field
	})
	return result
}
