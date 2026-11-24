package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kubescape/opa-utils/reporthandling/apis"
)

// CompareReportSets compares one side that may contain several framework-scoped
// reports against another side that may likewise contain one or more reports.
// It fails closed on unreadable inputs, inconsistent same-side targets,
// coverage gaps, conflicts, and identity-system mismatches.
func CompareReportSets(basePaths, headPaths []string, options Options) (*MultiChangeSet, error) {
	granularity, err := normalizeGranularity(options.Granularity)
	if err != nil {
		return nil, err
	}
	base, err := loadReportSet(basePaths, SideBase)
	if err != nil {
		return nil, err
	}
	head, err := loadReportSet(headPaths, SideHead)
	if err != nil {
		return nil, err
	}
	return compareLoadedSets(base, head, granularity), nil
}

// CompareReportSetBytes is the in-memory equivalent of CompareReportSets.
func CompareReportSetBytes(baseItems, headItems [][]byte, options Options) (*MultiChangeSet, error) {
	granularity, err := normalizeGranularity(options.Granularity)
	if err != nil {
		return nil, err
	}
	base, err := buildReportSet(baseItems)
	if err != nil {
		return nil, fmt.Errorf("loading base report set: %w", err)
	}
	head, err := buildReportSet(headItems)
	if err != nil {
		return nil, fmt.Errorf("loading head report set: %w", err)
	}
	return compareLoadedSets(base, head, granularity), nil
}

type controlRef struct {
	resourceID string
	controlID  string
}

type controlSourceState struct {
	source   Source
	control  controlEntry
	severity string
}

type frameworkSideView struct {
	report          *scanReport
	conflicts       []Conflict
	adjustments     []MetadataAdjustment
	controlSources  map[controlRef][]controlSourceState
	severityValues  map[string][]string
	allSummaries    map[string]controlSummary
	adjustmentAdded map[string]struct{}
}

func compareLoadedSets(baseSet, headSet *reportSet, granularity Granularity) *MultiChangeSet {
	m := &MultiChangeSet{SchemaVersion: multiSchemaVersion}
	m.Sources = append(m.Sources, baseSet.sources...)
	m.Sources = append(m.Sources, headSet.sources...)
	sort.Slice(m.Sources, func(i, j int) bool { return m.Sources[i].ID < m.Sources[j].ID })
	m.DuplicateReports = append(m.DuplicateReports, baseSet.duplicates...)
	m.DuplicateReports = append(m.DuplicateReports, headSet.duplicates...)
	sort.Slice(m.DuplicateReports, func(i, j int) bool { return m.DuplicateReports[i].SourceID < m.DuplicateReports[j].SourceID })
	for _, dup := range m.DuplicateReports {
		m.Warnings = append(m.Warnings, dup.Reason)
	}
	for i := range baseSet.manifestConflicts {
		if baseSet.manifestConflicts[i].Side == "" || baseSet.manifestConflicts[i].Side == "merged" {
			baseSet.manifestConflicts[i].Side = SideBase
		}
	}
	for i := range headSet.manifestConflicts {
		if headSet.manifestConflicts[i].Side == "" || headSet.manifestConflicts[i].Side == "merged" {
			headSet.manifestConflicts[i].Side = SideHead
		}
	}
	m.Conflicts = append(m.Conflicts, baseSet.manifestConflicts...)
	m.Conflicts = append(m.Conflicts, headSet.manifestConflicts...)
	m.MetadataAdjustments = append(m.MetadataAdjustments, baseSet.manifestAdjustments...)
	m.MetadataAdjustments = append(m.MetadataAdjustments, headSet.manifestAdjustments...)

	if mismatch := identitySystemMismatch(baseSet, headSet); mismatch != nil {
		m.IdentityMismatches = append(m.IdentityMismatches, *mismatch)
		m.Conflicts = append(m.Conflicts, collectSideConflicts(baseSet, SideBase, granularity)...)
		m.Conflicts = append(m.Conflicts, collectSideConflicts(headSet, SideHead, granularity)...)
		finalizeMulti(m)
		return m
	}

	frameworks := unionFrameworks(baseSet, headSet)
	baseDeclared := frameworkNameSet(baseSet)
	headDeclared := frameworkNameSet(headSet)
	targetMismatch := knownTargetMismatch(baseSet.targetID, headSet.targetID)
	if targetMismatch {
		m.IdentityMismatches = append(m.IdentityMismatches, IdentityMismatch{
			Category: CategoryIdentityMismatch,
			Layer:    "target",
			Reason:   fmt.Sprintf("base target identity %q and head target identity %q do not match; same-named resources are not merged by name", baseSet.targetID, headSet.targetID),
			Left:     &Identity{TargetID: baseSet.targetID},
			Right:    &Identity{TargetID: headSet.targetID},
		})
	}
	commonTarget := ""
	if !targetMismatch {
		if baseSet.targetID != targetIdentityUnknown {
			commonTarget = baseSet.targetID
		} else {
			commonTarget = headSet.targetID
		}
	}

	agg := newAggregateIndex()
	coverageSeen := make(map[string]struct{})
	mismatchSeen := make(map[string]struct{})

	for _, fw := range frameworks {
		baseKnown := fw == UnattributedFramework || baseDeclared[fw]
		headKnown := fw == UnattributedFramework || headDeclared[fw]

		if fw != UnattributedFramework && baseKnown != headKnown {
			onlySide := SideBase
			missingSide := SideHead
			if headKnown {
				onlySide = SideHead
				missingSide = SideBase
			}
			reason := fmt.Sprintf("framework %q is present only on the %s side; its findings are coverage changes, not new or resolved changes", fw, onlySide)
			m.CoverageChanges = append(m.CoverageChanges, CoverageChange{
				Category:  CategoryCoverageFrameworkSide,
				Side:      missingSide,
				Framework: fw,
				Reason:    reason,
			})
			view := buildFrameworkSide(sideSetFor(baseSet, headSet, onlySide), fw, granularity)
			for i := range view.conflicts {
				view.conflicts[i].Side = onlySide
			}
			m.Conflicts = append(m.Conflicts, view.conflicts...)
			m.MetadataAdjustments = append(m.MetadataAdjustments, view.adjustments...)
			for _, change := range failedChangesFromView(view, onlySide, fw, commonTarget, granularity) {
				change.Reason = reason
				change.TargetID = commonTarget
				m.Incomparable = append(m.Incomparable, change)
				fc := FrameworkChange{ControlChange: change, Framework: fw, Category: CategoryCoverageFrameworkSide}
				m.FrameworkChanges = append(m.FrameworkChanges, fc)
				agg.add(fc)
			}
			continue
		}

		baseView := buildFrameworkSide(baseSet, fw, granularity)
		headView := buildFrameworkSide(headSet, fw, granularity)
		for i := range baseView.conflicts {
			baseView.conflicts[i].Side = SideBase
		}
		for i := range headView.conflicts {
			headView.conflicts[i].Side = SideHead
		}
		m.Conflicts = append(m.Conflicts, baseView.conflicts...)
		m.Conflicts = append(m.Conflicts, headView.conflicts...)
		m.MetadataAdjustments = append(m.MetadataAdjustments, baseView.adjustments...)
		m.MetadataAdjustments = append(m.MetadataAdjustments, headView.adjustments...)

		cs := compareReports(baseView.report, headView.report, granularity)
		m.Warnings = append(m.Warnings, cs.Warnings...)
		for _, bucket := range []struct {
			changes  []ControlChange
			category string
		}{
			{cs.New, CategoryFrameworkNew},
			{cs.Resolved, CategoryFrameworkResolved},
			{cs.Unchanged, CategoryFrameworkUnchanged},
			{cs.Incomparable, CategoryFrameworkIncomparable},
		} {
			for _, change := range bucket.changes {
				change.TargetID = commonTarget
				change.EvidenceRef = evidenceReference(change)
				fc := FrameworkChange{ControlChange: change, Framework: fw, Category: bucket.category}
				m.FrameworkChanges = append(m.FrameworkChanges, fc)
				agg.add(fc)
				addCoverageFromChange(m, coverageSeen, change, fw, baseView, headView)
				addIdentityMismatchFromChange(m, mismatchSeen, change)
			}
		}
	}

	for _, conflict := range m.Conflicts {
		change := conflictChange(conflict)
		agg.addConflict(conflict.Identity, change)
	}

	m.MetadataAdjustments = dedupeAdjustments(m.MetadataAdjustments)
	m.Conflicts = dedupeConflicts(m.Conflicts)
	m.CoverageChanges = dedupeCoverage(m.CoverageChanges)
	m.IdentityMismatches = dedupeIdentityMismatches(m.IdentityMismatches)

	m.New, m.Resolved, m.Unchanged, m.Incomparable = agg.resolve(targetMismatch, baseSet.targetID, headSet.targetID)
	if targetMismatch {
		reason := "target identity layers do not match; all same-name matches are incomparable"
		m.New = nil
		m.Resolved = nil
		m.Unchanged = nil
		for i := range m.Incomparable {
			if m.Incomparable[i].Reason == "" {
				m.Incomparable[i].Reason = reason
			} else if !strings.Contains(m.Incomparable[i].Reason, "target identity") {
				m.Incomparable[i].Reason = reason + "; " + m.Incomparable[i].Reason
			}
		}
	}

	sortMulti(m)
	finalizeMulti(m)
	return m
}

func sideSetFor(baseSet, headSet *reportSet, side string) *reportSet {
	if side == SideBase {
		return baseSet
	}
	return headSet
}

func collectSideConflicts(set *reportSet, side string, granularity Granularity) []Conflict {
	var conflicts []Conflict
	for _, framework := range unionFrameworks(set, &reportSet{}) {
		view := buildFrameworkSide(set, framework, granularity)
		for i := range view.conflicts {
			view.conflicts[i].Side = side
		}
		conflicts = append(conflicts, view.conflicts...)
	}
	return conflicts
}

func knownTargetMismatch(baseTarget, headTarget string) bool {
	return baseTarget != targetIdentityUnknown && headTarget != targetIdentityUnknown && baseTarget != headTarget
}

func identitySystemMismatch(baseSet, headSet *reportSet) *IdentityMismatch {
	if baseSet.mixedIdentity {
		return &IdentityMismatch{
			Category:  CategoryIdentityMismatch,
			Layer:     "identitySystem",
			Reason:    "base report set mixes anonymized/pseudonymous and clear-text identifier systems; they cannot be compared as one identity group",
			SourceIDs: sourceIDs(baseSet.sources),
		}
	}
	if headSet.mixedIdentity {
		return &IdentityMismatch{
			Category:  CategoryIdentityMismatch,
			Layer:     "identitySystem",
			Reason:    "head report set mixes anonymized/pseudonymous and clear-text identifier systems; they cannot be compared as one identity group",
			SourceIDs: sourceIDs(headSet.sources),
		}
	}
	b, h := baseSet.identitySystem, headSet.identitySystem
	if b != identitySystemUnknown && h != identitySystemUnknown && b != h {
		return &IdentityMismatch{
			Category:  CategoryIdentityMismatch,
			Layer:     "identitySystem",
			Reason:    fmt.Sprintf("identifier systems differ: base=%s head=%s; anonymous identifiers are not reconstructed", b, h),
			Left:      &Identity{TargetID: b},
			Right:     &Identity{TargetID: h},
			SourceIDs: append(sourceIDs(baseSet.sources), sourceIDs(headSet.sources)...),
		}
	}
	return nil
}

func sourceIDs(sources []Source) []string {
	ids := make([]string, 0, len(sources))
	for _, source := range sources {
		ids = append(ids, source.ID)
	}
	sort.Strings(ids)
	return ids
}

func unionFrameworks(baseSet, headSet *reportSet) []string {
	seen := map[string]struct{}{UnattributedFramework: {}}
	for _, source := range append(append([]Source{}, baseSet.sources...), headSet.sources...) {
		for _, fw := range source.Frameworks {
			seen[fw] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for fw := range seen {
		result = append(result, fw)
	}
	sort.Strings(result)
	return result
}

func frameworkNameSet(set *reportSet) map[string]bool {
	result := make(map[string]bool)
	for _, source := range set.sources {
		for _, fw := range source.Frameworks {
			result[fw] = true
		}
	}
	return result
}

func buildFrameworkSide(set *reportSet, framework string, granularity Granularity) *frameworkSideView {
	view := &frameworkSideView{
		report: &scanReport{
			Results: []resultEntry{},
			SummaryDetails: summaryDetails{
				Controls: make(map[string]controlSummary),
			},
		},
		controlSources:  make(map[controlRef][]controlSourceState),
		severityValues:  make(map[string][]string),
		allSummaries:    make(map[string]controlSummary),
		adjustmentAdded: make(map[string]struct{}),
	}
	mergedControls := make(map[string]map[string]*controlEntry)
	resourceOrder := make([]string, 0)

	for _, loaded := range set.reports {
		report := loaded.report
		mergeMetadataInto(view.report, report)
		mergeCoverageInto(&view.report.ScanCoverage, report.ScanCoverage)
		for id, summary := range report.SummaryDetails.Controls {
			values := view.severityValues[id]
			value := severityFromSummary(summary)
			if len(values) == 0 || values[len(values)-1] != value {
				view.severityValues[id] = append(values, value)
			}
			existing := view.allSummaries[id]
			chosen, adjustments := mergeControlSummary(id, existing, summary)
			view.allSummaries[id] = chosen
			for _, adjustment := range adjustments {
				dedupKey := adjustment.ControlID + ":" + adjustment.Field + ":" + adjustment.Selected
				if _, added := view.adjustmentAdded[dedupKey]; added {
					continue
				}
				view.adjustmentAdded[dedupKey] = struct{}{}
				view.adjustments = append(view.adjustments, adjustment)
			}
		}

		// Preserve the framework's declared control scope even when a report
		// has no result entry for one of its controls.
		for _, fwSummary := range report.SummaryDetails.Frameworks {
			if fwSummary.Name != framework || fwSummary.Controls == nil {
				continue
			}
			if view.report.SummaryDetails.Frameworks == nil {
				view.report.SummaryDetails.Frameworks = []frameworkSummary{{Name: framework, Controls: map[string]controlSummary{}}}
			}
			fwMap := view.report.SummaryDetails.Frameworks[0].Controls
			for id, summary := range fwSummary.Controls {
				if _, exists := fwMap[id]; !exists {
					fwMap[id] = summary
				}
				if _, exists := view.report.SummaryDetails.Controls[id]; !exists {
					if chosen, ok := view.allSummaries[id]; ok {
						view.report.SummaryDetails.Controls[id] = chosen
					} else {
						view.report.SummaryDetails.Controls[id] = summary
					}
				}
			}
		}

		for _, result := range report.Results {
			if _, exists := mergedControls[result.ResourceID]; !exists {
				mergedControls[result.ResourceID] = make(map[string]*controlEntry)
				resourceOrder = append(resourceOrder, result.ResourceID)
			}
			for _, control := range result.AssociatedControls {
				if !containsString(controlFrameworks(report, control), framework) {
					continue
				}
				if frameworkScopeAllowsControl(report, framework, control.ControlID) {
					if summary, ok := view.allSummaries[control.ControlID]; ok {
						view.report.SummaryDetails.Controls[control.ControlID] = summary
					}
				}
				filterFrameworks := []string{framework}
				if framework == UnattributedFramework {
					filterFrameworks = nil
				}
				effective := effectiveControlForFrameworks(control, filterFrameworks)
				// The view has already applied framework filtering. Remove
				// exception bodies so compareReports does not reapply a broader
				// report-level filter and so internal views never carry raw
				// exception content into output structures.
				for i := range effective.Rules {
					effective.Rules[i].Exception = nil
				}
				ref := controlRef{resourceID: result.ResourceID, controlID: control.ControlID}
				severity := buildSeverityMap(report)[control.ControlID]
				view.controlSources[ref] = append(view.controlSources[ref], controlSourceState{
					source:   loaded.source,
					control:  effective,
					severity: severity,
				})
				current := mergedControls[result.ResourceID][control.ControlID]
				if current == nil {
					copyControl := mergeControlCopies(effective)
					mergedControls[result.ResourceID][control.ControlID] = &copyControl
				} else {
					mergeControlInto(current, effective)
				}
			}
		}
	}

	for _, resourceID := range resourceOrder {
		controlMap := mergedControls[resourceID]
		ids := make([]string, 0, len(controlMap))
		for id := range controlMap {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		entry := resultEntry{ResourceID: resourceID}
		for _, id := range ids {
			control := controlMap[id]
			entry.AssociatedControls = append(entry.AssociatedControls, *control)
		}
		view.report.Results = append(view.report.Results, entry)
	}
	if framework != UnattributedFramework {
		if len(view.report.SummaryDetails.Frameworks) == 0 {
			view.report.SummaryDetails.Frameworks = []frameworkSummary{{Name: framework, Controls: map[string]controlSummary{}}}
		}
	} else {
		view.report.SummaryDetails.Frameworks = nil
	}
	view.conflicts = detectConflicts(view, set.targetID, granularity)
	sort.Slice(view.conflicts, func(i, j int) bool {
		return view.conflicts[i].Identity.cacheKey() < view.conflicts[j].Identity.cacheKey()
	})
	return view
}

func failedChangesFromView(view *frameworkSideView, side, framework, targetID string, granularity Granularity) []ControlChange {
	if view == nil || view.report == nil {
		return nil
	}
	result := make([]ControlChange, 0)
	severities := buildSeverityMap(view.report)
	for key, control := range buildMap(view.report) {
		if control.Status.InnerStatus != string(apis.StatusFailed) {
			continue
		}
		for _, finding := range findingsForControl(key, control, severities[key.controlID], granularity) {
			change := finding.change(statusAbsent, statusAbsent, "")
			if side == SideBase {
				change.BaseStatus = string(apis.StatusFailed)
				change.HeadStatus = statusAbsent
			} else {
				change.BaseStatus = statusAbsent
				change.HeadStatus = string(apis.StatusFailed)
			}
			change.TargetID = targetID
			change.EvidenceRef = evidenceReference(change)
			result = append(result, change)
		}
	}
	sortChanges(result)
	return result
}

func detectConflicts(view *frameworkSideView, targetID string, granularity Granularity) []Conflict {
	var conflicts []Conflict
	for ref, states := range view.controlSources {
		if len(states) < 2 {
			continue
		}
		severity := ""
		failedByIdentity := make(map[string]Identity)
		failedSource := make(map[string]ConflictSource)
		for _, state := range states {
			if state.control.Status.InnerStatus != string(apis.StatusFailed) {
				continue
			}
			if severity == "" {
				severity = state.severity
			}
			key := key{resourceID: ref.resourceID, controlID: ref.controlID}
			for _, finding := range findingsForControl(key, state.control, state.severity, granularity) {
				id := identityFromChange(finding.change(string(apis.StatusFailed), string(apis.StatusFailed), ""))
				id.TargetID = targetID
				failedByIdentity[id.cacheKey()] = id
				failedSource[id.cacheKey()] = ConflictSource{
					SourceID:    state.source.ID,
					Status:      string(apis.StatusFailed),
					SubStatus:   state.control.Status.SubStatus,
					Severity:    state.severity,
					ControlName: state.control.Name,
				}
			}
		}
		for idKey, identity := range failedByIdentity {
			var opposing []ConflictSource
			for _, state := range states {
				if state.source.ID == failedSource[idKey].SourceID {
					continue
				}
				verdict, subStatus, conclusive := evidenceVerdictAgainst(state.control, identity)
				if conclusive && verdict != string(apis.StatusFailed) {
					opposing = append(opposing, ConflictSource{
						SourceID:    state.source.ID,
						Status:      verdict,
						SubStatus:   subStatus,
						Severity:    state.severity,
						ControlName: state.control.Name,
					})
				}
			}
			if len(opposing) == 0 {
				continue
			}
			sources := []ConflictSource{failedSource[idKey]}
			sources = append(sources, opposing...)
			sort.Slice(sources, func(i, j int) bool { return sources[i].SourceID < sources[j].SourceID })
			conflicts = append(conflicts, Conflict{
				Category: CategoryConflictEvidence,
				Side:     "", // filled by caller below if needed
				Identity: identity,
				Reason:   "same five-layer evidence has contradictory failed and conclusive non-failed conclusions in reports on one side",
				Sources:  dedupeConflictSources(sources),
			})
		}
	}
	return conflicts
}

func evidenceVerdictAgainst(control controlEntry, identity Identity) (status, subStatus string, conclusive bool) {
	if identity.EvidenceType == evidenceTypeControl {
		if isConclusiveNonFailure(control) {
			return control.Status.InnerStatus, control.Status.SubStatus, true
		}
		return control.Status.InnerStatus, control.Status.SubStatus, false
	}
	for _, rule := range control.Rules {
		if rule.Name != identity.RuleName {
			continue
		}
		if rule.Status == string(apis.StatusPassed) && rule.SubStatus != string(apis.SubStatusNotEvaluated) {
			return rule.Status, rule.SubStatus, true
		}
		if rule.Status != string(apis.StatusFailed) && rule.SubStatus != string(apis.SubStatusNotEvaluated) && rule.Status != "" {
			// Manual review/skipped is not a conclusive opposite verdict.
			return rule.Status, rule.SubStatus, false
		}
		return rule.Status, rule.SubStatus, false
	}
	if isConclusiveNonFailure(control) {
		return control.Status.InnerStatus, control.Status.SubStatus, true
	}
	return control.Status.InnerStatus, control.Status.SubStatus, false
}

func conflictChange(conflict Conflict) ControlChange {
	c := ControlChange{
		TargetID:           conflict.Identity.TargetID,
		ResourceID:         conflict.Identity.ResourceID,
		ControlID:          conflict.Identity.ControlID,
		RuleName:           conflict.Identity.RuleName,
		EvidenceType:       conflict.Identity.EvidenceType,
		Path:               conflict.Identity.Path,
		EvidenceResourceID: conflict.Identity.EvidenceResourceID,
		Severity:           firstConflictSeverity(conflict.Sources),
		BaseStatus:         string(apis.StatusFailed),
		HeadStatus:         statusAbsent,
		Reason:             conflict.Reason,
		SourceIDs:          conflictSourceIDs(conflict.Sources),
		EvidenceRef:        evidenceReferenceFromIdentity(conflict.Identity),
	}
	if conflict.Side == SideHead {
		c.BaseStatus = statusAbsent
		c.HeadStatus = string(apis.StatusFailed)
	}
	return c
}

func firstConflictSeverity(sources []ConflictSource) string {
	best := ""
	bestRank := -1
	for _, source := range sources {
		rank := severityRank(source.Severity)
		if rank > bestRank {
			bestRank = rank
			best = source.Severity
		}
	}
	return best
}

func conflictSourceIDs(sources []ConflictSource) []string {
	ids := make([]string, 0, len(sources))
	for _, source := range sources {
		ids = append(ids, source.SourceID)
	}
	sort.Strings(ids)
	return compactStrings(ids)
}

func addCoverageFromChange(m *MultiChangeSet, seen map[string]struct{}, change ControlChange, framework string, baseView, headView *frameworkSideView) {
	category := coverageCategoryForReason(change.Reason)
	side := coverageSideFromReason(change.Reason)
	reason := change.Reason

	// Existing comparison wording deliberately stays stable for single-report
	// output. For report sets, recover the precise coverage state from the
	// normalized framework view and give coverage consumers a direct reason.
	if category == "" || category == CategoryCoverageScopeMismatch {
		if incompleteReason := viewIncompleteReason(baseView, change, SideBase); incompleteReason != "" {
			category = CategoryCoverageIncomplete
			side = SideBase
			reason = incompleteReason
		} else if incompleteReason := viewIncompleteReason(headView, change, SideHead); incompleteReason != "" {
			category = CategoryCoverageIncomplete
			side = SideHead
			reason = incompleteReason
		}
	}
	if category == "" {
		return
	}
	item := CoverageChange{
		Category:   category,
		Side:       side,
		Framework:  framework,
		TargetID:   change.TargetID,
		ResourceID: change.ResourceID,
		ControlID:  change.ControlID,
		Reason:     reason,
	}
	key := item.Category + "|" + item.Side + "|" + item.Framework + "|" + item.ResourceID + "|" + item.ControlID + "|" + item.Reason
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	m.CoverageChanges = append(m.CoverageChanges, item)
}

func coverageSideFromReason(reason string) string {
	switch {
	case strings.Contains(reason, "base "):
		return SideBase
	case strings.Contains(reason, "head "):
		return SideHead
	default:
		return ""
	}
}

func viewIncompleteReason(view *frameworkSideView, change ControlChange, side string) string {
	if view == nil || view.report == nil {
		return ""
	}
	key := key{resourceID: change.ResourceID, controlID: change.ControlID}
	control, ok := buildMap(view.report)[key]
	if !ok {
		for _, nc := range view.report.ScanCoverage.NotEvaluatedControls {
			if nc.ControlID == change.ControlID {
				return fmt.Sprintf("%s control %s was not evaluated: %s", side, change.ControlID, nc.Reason)
			}
		}
		if coverageGapAffects(view.report.ScanCoverage, change.ControlID) {
			return fmt.Sprintf("%s report has degraded scan coverage affecting control %s; the change is incomparable", side, change.ControlID)
		}
		return ""
	}
	if control.Status.SubStatus == string(apis.SubStatusNotEvaluated) {
		return fmt.Sprintf("%s control %s was not evaluated (evaluation incomplete, subStatus=%s); missing evidence cannot be classified as new or resolved", side, change.ControlID, apis.SubStatusNotEvaluated)
	}
	for _, rule := range control.Rules {
		if rule.Name == change.RuleName && rule.SubStatus == string(apis.SubStatusNotEvaluated) {
			return fmt.Sprintf("%s rule %q for control %s was not evaluated; missing evidence cannot be classified as new or resolved", side, rule.Name, change.ControlID)
		}
	}
	for _, nc := range view.report.ScanCoverage.NotEvaluatedControls {
		if nc.ControlID == change.ControlID {
			return fmt.Sprintf("%s control %s was not evaluated: %s", side, change.ControlID, nc.Reason)
		}
	}
	if coverageGapAffects(view.report.ScanCoverage, change.ControlID) {
		return fmt.Sprintf("%s report has degraded scan coverage affecting control %s; the change is incomparable", side, change.ControlID)
	}
	return ""
}

func coverageCategoryForReason(reason string) string {
	switch {
	case reason == "":
		return ""
	case strings.Contains(reason, "different failed evidence detail"):
		return ""
	case strings.Contains(reason, "not present in") && strings.Contains(reason, "declared control scope"):
		return CategoryCoverageControlScope
	case strings.Contains(reason, "not evaluated") || strings.Contains(reason, "degraded scan coverage"):
		return CategoryCoverageIncomplete
	case strings.Contains(reason, "scan target types differ") ||
		strings.Contains(reason, "scanning targets differ") ||
		strings.Contains(reason, "cluster contexts differ") ||
		strings.Contains(reason, "namespaces differ") ||
		strings.Contains(reason, "target names differ") ||
		strings.Contains(reason, "repository identities differ"):
		return CategoryCoverageScopeMismatch
	default:
		return ""
	}
}

func addIdentityMismatchFromChange(m *MultiChangeSet, seen map[string]struct{}, change ControlChange) {
	if !strings.Contains(change.Reason, "different failed evidence detail") {
		return
	}
	id := identityFromChange(change)
	key := id.cacheKey()
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	m.IdentityMismatches = append(m.IdentityMismatches, IdentityMismatch{
		Category: CategoryIdentityMismatch,
		Layer:    "rule/evidence",
		Reason:   change.Reason,
		Left:     &id,
	})
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func frameworkScopeAllowsControl(report *scanReport, framework, controlID string) bool {
	if framework == UnattributedFramework {
		return true
	}
	for _, fw := range report.SummaryDetails.Frameworks {
		if fw.Name != framework {
			continue
		}
		if len(fw.Controls) == 0 {
			return true
		}
		_, ok := fw.Controls[controlID]
		return ok
	}
	return true
}
