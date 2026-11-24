package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type mergeManifest struct {
	Version          string               `json:"version"`
	SourceSHA256     []string             `json:"sourceSHA256,omitempty"`
	Sources          []Source             `json:"sources,omitempty"`
	TargetID         string               `json:"targetID,omitempty"`
	IdentitySystem   string               `json:"identitySystem,omitempty"`
	ScoreMethod      string               `json:"scoreMethod,omitempty"`
	Conflicts        []Conflict           `json:"conflicts,omitempty"`
	Adjustments      []MetadataAdjustment `json:"adjustments,omitempty"`
	CoverageWarnings []string             `json:"coverageWarnings,omitempty"`
}

type loadedReport struct {
	path   string
	paths  []string
	data   []byte
	sha256 string
	source Source
	report *scanReport
}

type reportSet struct {
	reports             []*loadedReport
	sources             []Source
	duplicates          []DuplicateReport
	targetID            string
	identitySystem      string
	mixedIdentity       bool
	manifestConflicts   []Conflict
	manifestAdjustments []MetadataAdjustment
}

type targetFingerprint struct {
	ExplicitTargetID  string   `json:"explicitTargetID,omitempty"`
	ClusterName       string   `json:"clusterName,omitempty"`
	ContextName       string   `json:"contextName,omitempty"`
	RepoIdentity      string   `json:"repoIdentity,omitempty"`
	TargetType        string   `json:"targetType,omitempty"`
	ScanningTarget    string   `json:"scanningTarget,omitempty"`
	IncludeNamespaces []string `json:"includeNamespaces,omitempty"`
	ExcludeNamespaces []string `json:"excludeNamespaces,omitempty"`
	TargetNames       []string `json:"targetNames,omitempty"`
}

var pseudonymPattern = regexp.MustCompile(`(?:^|[-_/.])(?:res|ns|sa|ref|lbl|img|ksresource|pseudonym)?-?[0-9a-f]{32}(?:-\d+)?(?:$|[-_/.])`)

func loadReportSet(paths []string, side string) (*reportSet, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("%s side has no report: provide at least one report; an empty side is not treated as all-resolved", side)
	}
	items := make([][]byte, 0, len(paths))
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("%s report path cannot be empty", side)
		}
		data, err := readReport(path)
		if err != nil {
			// readReport already names the path for size/non-regular errors;
			// wrap os.Open errors with the side and argument as well.
			return nil, fmt.Errorf("%s report %q cannot be read: %w", side, path, err)
		}
		items = append(items, data)
	}
	set, err := buildReportSetLabeled(items, paths)
	if err != nil {
		// Parse errors from byte construction do not know which argument. Find
		// the offending path by re-validating in argument order. This does not
		// reread after a successful size check beyond the already bounded helper.
		for i, path := range paths {
			if i >= len(items) {
				break
			}
			if _, parseErr := parseReport(items[i]); parseErr != nil {
				if errors.Is(parseErr, ErrEncryptedReport) {
					return nil, fmt.Errorf("%s report %q is encrypted: decrypt first with 'kubescape decrypt': %w", side, path, ErrEncryptedReport)
				}
				if ReportKindOfJSON(items[i]) == VulnerabilityReport {
					return nil, fmt.Errorf("%s report %q is an image vulnerability report: %w", side, path, ErrMixedReportKinds)
				}
				return nil, fmt.Errorf("%s report %q has the wrong type or shape: %w", side, path, parseErr)
			}
		}
		return nil, err
	}
	return set, nil
}

// LoadReportSetPaths validates and loads a group of posture report paths. It is
// exported for callers that need the same all-or-nothing group validation as
// CompareReportSets.
func LoadReportSetPaths(paths []string) ([]Source, error) {
	set, err := loadReportSet(paths, "report-set")
	if err != nil {
		return nil, err
	}
	return set.sources, nil
}

func buildReportSet(items [][]byte) (*reportSet, error) {
	return buildReportSetLabeled(items, nil)
}

func buildReportSetLabeled(items [][]byte, labels []string) (*reportSet, error) {
	set := &reportSet{targetID: targetIdentityUnknown}
	byHash := make(map[string]*loadedReport)
	identitySystems := make(map[string]struct{})
	targets := make(map[string]targetFingerprint)

	for itemIndex, data := range items {
		itemLabel := ""
		if itemIndex < len(labels) {
			itemLabel = labels[itemIndex]
		}
		if len(data) > maxReportSize {
			return nil, fmt.Errorf("%w: exceeds the %d byte limit", errReportTooLarge, int64(maxReportSize))
		}
		if ReportKindOfJSON(data) == VulnerabilityReport {
			return nil, fmt.Errorf("image vulnerability reports are not supported by framework report sets: %w", ErrMixedReportKinds)
		}
		report, err := parseReport(data)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		fullHash := hex.EncodeToString(sum[:])
		if existing, ok := byHash[fullHash]; ok {
			existing.source.DuplicateCopies++
			if itemLabel != "" {
				existing.paths = append(existing.paths, itemLabel)
			}
			continue
		}

		tf := targetFingerprintOf(report)
		targetID := targetIDOf(tf)
		system := identitySystemOf(report)
		identitySystems[system] = struct{}{}
		targets[fullHash] = tf

		loaded := &loadedReport{
			path:   itemLabel,
			paths:  compactStrings([]string{itemLabel}),
			data:   data,
			sha256: fullHash,
			report: report,
			source: Source{
				ID:              "src_" + fullHash[:12],
				SHA256:          fullHash,
				Frameworks:      reportFrameworkNames(report),
				TargetID:        targetID,
				IdentitySystem:  system,
				DuplicateCopies: 1,
			},
		}
		byHash[fullHash] = loaded
		set.reports = append(set.reports, loaded)
	}

	sort.Slice(set.reports, func(i, j int) bool { return set.reports[i].sha256 < set.reports[j].sha256 })
	for _, loaded := range set.reports {
		set.sources = append(set.sources, loaded.source)
		if loaded.source.DuplicateCopies > 1 {
			set.duplicates = append(set.duplicates, DuplicateReport{
				Category: CategoryDuplicateReport,
				SourceID: loaded.source.ID,
				Copies:   loaded.source.DuplicateCopies,
				Reason:   fmt.Sprintf("byte-identical report was supplied %d times; merged once", loaded.source.DuplicateCopies),
			})
		}
	}
	sort.Slice(set.duplicates, func(i, j int) bool { return set.duplicates[i].SourceID < set.duplicates[j].SourceID })

	knownSystems := 0
	for system := range identitySystems {
		if system != identitySystemUnknown {
			set.identitySystem = system
			knownSystems++
		}
	}
	if _, anon := identitySystems[identitySystemAnonymized]; anon {
		if _, plain := identitySystems[identitySystemCleartext]; plain || knownSystems > 1 {
			set.mixedIdentity = true
			set.identitySystem = "mixed"
		} else {
			set.identitySystem = identitySystemAnonymized
		}
	} else if _, plain := identitySystems[identitySystemCleartext]; plain {
		set.identitySystem = identitySystemCleartext
	} else if set.identitySystem == "" {
		set.identitySystem = identitySystemUnknown
	}
	if len(identitySystems) > 1 {
		set.mixedIdentity = true
		if set.identitySystem == "" || set.identitySystem == identitySystemUnknown {
			set.identitySystem = "mixed"
		}
	}

	knownTarget := ""
	for i := 0; i < len(set.reports); i++ {
		left := set.reports[i]
		leftTF := targets[left.sha256]
		leftID := targetIDOf(leftTF)
		if leftID != targetIdentityUnknown && knownTarget == "" {
			knownTarget = leftID
			set.targetID = leftID
		}
		for j := i + 1; j < len(set.reports); j++ {
			right := set.reports[j]
			rightTF := targets[right.sha256]
			if reason := targetScopeDifference(leftTF, rightTF); reason != "" {
				return nil, fmt.Errorf("reports on the same side have inconsistent target or scope between %s and %s: %s",
					reportIdentityLabel(left), reportIdentityLabel(right), reason)
			}
			rightID := targetIDOf(rightTF)
			if knownTarget != "" && rightID != targetIdentityUnknown && knownTarget != rightID {
				return nil, fmt.Errorf("reports on the same side have inconsistent target or scope between %s and %s: target identities %q vs %q",
					reportIdentityLabel(left), reportIdentityLabel(right), knownTarget, rightID)
			}
			if rightID != targetIdentityUnknown && knownTarget == "" {
				knownTarget = rightID
				set.targetID = rightID
			}
		}
	}
	adoptMergeManifests(set)
	return set, nil
}

func adoptMergeManifests(set *reportSet) {
	var manifestSources []Source
	for _, loaded := range set.reports {
		manifest := loaded.report.DiffMerge
		if manifest == nil {
			continue
		}
		set.manifestConflicts = append(set.manifestConflicts, manifest.Conflicts...)
		set.manifestAdjustments = append(set.manifestAdjustments, manifest.Adjustments...)
		manifestSources = append(manifestSources, manifest.Sources...)
		if manifest.TargetID != "" && set.targetID == targetIdentityUnknown {
			set.targetID = manifest.TargetID
		}
		if manifest.IdentitySystem != "" {
			set.identitySystem = manifest.IdentitySystem
		}
	}
	if len(manifestSources) == 0 {
		return
	}
	set.sources = dedupeSources(manifestSources)
	set.duplicates = nil
	for _, source := range set.sources {
		if source.DuplicateCopies > 1 {
			set.duplicates = append(set.duplicates, DuplicateReport{
				Category: CategoryDuplicateReport,
				SourceID: source.ID,
				Copies:   source.DuplicateCopies,
				Reason:   fmt.Sprintf("byte-identical report was supplied %d times; merged once", source.DuplicateCopies),
			})
		}
	}
	sort.Slice(set.duplicates, func(i, j int) bool { return set.duplicates[i].SourceID < set.duplicates[j].SourceID })
}

func dedupeSources(items []Source) []Source {
	byID := map[string]Source{}
	for _, source := range items {
		current, ok := byID[source.ID]
		if !ok {
			byID[source.ID] = source
			continue
		}
		if source.DuplicateCopies > current.DuplicateCopies {
			current.DuplicateCopies = source.DuplicateCopies
		}
		if current.TargetID == "" {
			current.TargetID = source.TargetID
		}
		if current.IdentitySystem == "" {
			current.IdentitySystem = source.IdentitySystem
		}
		current.Frameworks = compactStrings(append(current.Frameworks, source.Frameworks...))
		byID[source.ID] = current
	}
	result := make([]Source, 0, len(byID))
	for _, source := range byID {
		result = append(result, source)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

type targetConflict struct {
	a, b, reason string
}

func reportIdentityLabel(report *loadedReport) string {
	if report == nil {
		return "unknown-report"
	}
	if strings.TrimSpace(report.path) != "" {
		return fmt.Sprintf("%s (%s)", report.path, report.source.ID)
	}
	return report.source.ID
}

func targetFingerprintOf(report *scanReport) targetFingerprint {
	if report == nil {
		return targetFingerprint{}
	}
	scan := report.Metadata.ScanMetadata
	tf := targetFingerprint{
		TargetType:        strings.TrimSpace(scan.TargetType),
		IncludeNamespaces: canonicalSet(scan.IncludeNamespaces),
		ExcludeNamespaces: canonicalSet(scan.ExcludedNamespaces),
		TargetNames:       canonicalSet(scan.TargetNames),
		ClusterName:       strings.TrimSpace(report.ClusterName),
	}
	if scan.ScanningTarget != nil {
		tf.ScanningTarget = fmt.Sprintf("%d", *scan.ScanningTarget)
	}
	tm := report.Metadata.TargetMetadata
	tf.ExplicitTargetID = strings.TrimSpace(tm.TargetID)
	if tm.Cluster != nil {
		tf.ContextName = strings.TrimSpace(tm.Cluster.ContextName)
	}
	if tm.Repo != nil {
		tf.RepoIdentity = repositoryIdentity(tm.Repo)
	}
	return tf
}

func targetIDOf(tf targetFingerprint) string {
	if tf.ExplicitTargetID != "" {
		return "target:" + tf.ExplicitTargetID
	}
	// A target with no identifying scope is unknown, not a hash of empty
	// fields: hashing would create a fake stable identity and merge unrelated
	// reports that both omit metadata. canonicalSet can turn nil slices into
	// non-nil empty slices, so compare logical emptiness rather than DeepEqual.
	if tf.ClusterName == "" && tf.ContextName == "" && tf.RepoIdentity == "" &&
		tf.TargetType == "" && tf.ScanningTarget == "" &&
		len(tf.IncludeNamespaces) == 0 && len(tf.ExcludeNamespaces) == 0 && len(tf.TargetNames) == 0 {
		return targetIdentityUnknown
	}
	data, _ := json.Marshal(tf)
	sum := sha256.Sum256(data)
	return "target_" + hex.EncodeToString(sum[:])[:16]
}

func targetScopeDifference(a, b targetFingerprint) string {
	var reasons []string
	if a.ExplicitTargetID != b.ExplicitTargetID && nonEmptyPair(a.ExplicitTargetID, b.ExplicitTargetID) {
		reasons = append(reasons, fmt.Sprintf("targetID %q vs %q", a.ExplicitTargetID, b.ExplicitTargetID))
	}
	if a.ClusterName != b.ClusterName && nonEmptyPair(a.ClusterName, b.ClusterName) {
		reasons = append(reasons, fmt.Sprintf("clusterName %q vs %q", a.ClusterName, b.ClusterName))
	}
	if a.ContextName != b.ContextName && nonEmptyPair(a.ContextName, b.ContextName) {
		reasons = append(reasons, fmt.Sprintf("cluster context %q vs %q", a.ContextName, b.ContextName))
	}
	if a.RepoIdentity != b.RepoIdentity && nonEmptyPair(a.RepoIdentity, b.RepoIdentity) {
		reasons = append(reasons, fmt.Sprintf("repository %q vs %q", a.RepoIdentity, b.RepoIdentity))
	}
	if a.TargetType != b.TargetType && nonEmptyPair(a.TargetType, b.TargetType) {
		reasons = append(reasons, fmt.Sprintf("target type %q vs %q", a.TargetType, b.TargetType))
	}
	if a.ScanningTarget != b.ScanningTarget && nonEmptyPair(a.ScanningTarget, b.ScanningTarget) {
		reasons = append(reasons, fmt.Sprintf("scanning target %q vs %q", a.ScanningTarget, b.ScanningTarget))
	}
	if !equalStringSlices(a.IncludeNamespaces, b.IncludeNamespaces) && (len(a.IncludeNamespaces) > 0 || len(b.IncludeNamespaces) > 0) {
		reasons = append(reasons, fmt.Sprintf("included namespaces %v vs %v", a.IncludeNamespaces, b.IncludeNamespaces))
	}
	if !equalStringSlices(a.ExcludeNamespaces, b.ExcludeNamespaces) && (len(a.ExcludeNamespaces) > 0 || len(b.ExcludeNamespaces) > 0) {
		reasons = append(reasons, fmt.Sprintf("excluded namespaces %v vs %v", a.ExcludeNamespaces, b.ExcludeNamespaces))
	}
	if !equalStringSlices(a.TargetNames, b.TargetNames) && (len(a.TargetNames) > 0 || len(b.TargetNames) > 0) {
		reasons = append(reasons, fmt.Sprintf("target names %v vs %v", a.TargetNames, b.TargetNames))
	}
	return strings.Join(reasons, "; ")
}

func nonEmptyPair(a, b string) bool {
	return strings.TrimSpace(a) != "" && strings.TrimSpace(b) != ""
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func identitySystemOf(report *scanReport) string {
	if report == nil {
		return identitySystemUnknown
	}
	if explicit := strings.ToLower(strings.TrimSpace(report.IdentitySystem)); explicit != "" {
		switch explicit {
		case identitySystemAnonymized, "anonymous", "pseudonymized", "hide":
			return identitySystemAnonymized
		case identitySystemCleartext, "plain", "plaintext", "clear":
			return identitySystemCleartext
		default:
			return explicit
		}
	}
	for _, result := range report.Results {
		if pseudonymPattern.MatchString(result.ResourceID) {
			return identitySystemAnonymized
		}
		for _, control := range result.AssociatedControls {
			for _, rule := range control.Rules {
				for _, path := range rule.Paths {
					if pseudonymPattern.MatchString(path.ResourceID) {
						return identitySystemAnonymized
					}
				}
			}
		}
	}
	return identitySystemCleartext
}

func reportFrameworkNames(report *scanReport) []string {
	if report == nil {
		return nil
	}
	seen := make(map[string]struct{})
	for _, fw := range report.SummaryDetails.Frameworks {
		name := strings.TrimSpace(fw.Name)
		if name != "" {
			seen[name] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func controlFrameworks(report *scanReport, control controlEntry) []string {
	seen := make(map[string]struct{})
	for _, name := range control.FrameworkNames {
		if name = strings.TrimSpace(name); name != "" {
			seen[name] = struct{}{}
		}
	}
	for _, fw := range report.SummaryDetails.Frameworks {
		if fw.Name == "" {
			continue
		}
		if _, ok := fw.Controls[control.ControlID]; ok {
			seen[fw.Name] = struct{}{}
		}
	}
	if len(seen) == 0 && len(report.SummaryDetails.Frameworks) == 1 && report.SummaryDetails.Frameworks[0].Name != "" {
		// Attribute to the only framework even when its declared control map
		// omits the ID. The framework view keeps that ID out of its scope
		// summary, which lets comparison classify it as control-out-of-scope.
		seen[report.SummaryDetails.Frameworks[0].Name] = struct{}{}
	}
	if len(seen) == 0 {
		return []string{UnattributedFramework}
	}
	result := make([]string, 0, len(seen))
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// reportFileNameOnly is retained for callers that need a non-absolute label.
// New output uses content IDs instead; errors may still name the supplied path.
func reportFileNameOnly(path string) string {
	return filepath.Base(filepath.Clean(path))
}
