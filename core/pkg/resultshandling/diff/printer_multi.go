package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"sigs.k8s.io/yaml"
)

// PrintMultiJSON writes the full framework-aware result as deterministic JSON.
func PrintMultiJSON(w io.Writer, result *MultiChangeSet) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = io.WriteString(w, "\n")
	return err
}

// PrintMultiYAML writes the full framework-aware result as deterministic YAML.
func PrintMultiYAML(w io.Writer, result *MultiChangeSet) error {
	data, err := yaml.Marshal(result)
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// PrintMultiPretty prints aggregate unique counts first, then framework and
// coverage details. Aggregate wording remains compatible with the existing
// human-readable diff口径.
func PrintMultiPretty(w io.Writer, result *MultiChangeSet) error {
	if result == nil {
		_, err := io.WriteString(w, "No report-set diff result.\n")
		return err
	}
	counts := result.Counts
	var b strings.Builder
	fmt.Fprintf(&b, "Report-set comparison (%s)\n", result.SchemaVersion)
	fmt.Fprintf(&b, "Aggregate unique findings: %d new, %d resolved, %d unchanged, %d incomparable\n",
		counts.New, counts.Resolved, counts.Unchanged, counts.Incomparable)
	fmt.Fprintf(&b, "Framework changes: %d new, %d resolved, %d unchanged, %d incomparable/coverage-blocked\n",
		counts.FrameworkNew, counts.FrameworkResolved, counts.FrameworkUnchanged, counts.FrameworkOther)
	fmt.Fprintf(&b, "Coverage changes: %d; conflicts: %d; identity mismatches: %d; duplicate reports merged: %d\n\n",
		counts.CoverageChanges, counts.Conflicts, counts.IdentityMismatches, counts.DuplicateReports)

	writePrettyChanges(&b, "New aggregate findings", result.New)
	writePrettyChanges(&b, "Resolved aggregate findings", result.Resolved)
	writePrettyChanges(&b, "Unchanged aggregate findings", result.Unchanged)
	writePrettyChanges(&b, "Incomparable aggregate findings", result.Incomparable)

	if len(result.FrameworkChanges) > 0 {
		b.WriteString("Framework-level changes\n")
		for _, change := range result.FrameworkChanges {
			fmt.Fprintf(&b, "  [%s] framework=%s resource=%s control=%s rule=%s evidenceType=%s path=%s evidenceRef=%s",
				change.Category, change.Framework, change.ResourceID,
				change.ControlID, change.RuleName, change.EvidenceType, change.Path, change.EvidenceRef)
			if change.Reason != "" {
				fmt.Fprintf(&b, " reason=%q", change.Reason)
			}
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}
	if len(result.CoverageChanges) > 0 {
		b.WriteString("Coverage changes (not counted as new or resolved)\n")
		for _, item := range result.CoverageChanges {
			fmt.Fprintf(&b, "  [%s] side=%s framework=%s control=%s resource=%s: %s\n",
				item.Category, item.Side, item.Framework, item.ControlID, item.ResourceID, item.Reason)
		}
		b.WriteByte('\n')
	}
	if len(result.Conflicts) > 0 {
		b.WriteString("Evidence conclusion conflicts (gate failure)\n")
		for _, conflict := range result.Conflicts {
			fmt.Fprintf(&b, "  [%s] side=%s %s/%s/%s/%s: %s\n",
				conflict.Category, conflict.Side, conflict.Identity.TargetID, conflict.Identity.ResourceID,
				conflict.Identity.ControlID, conflict.Identity.RuleName, conflict.Reason)
			for _, source := range conflict.Sources {
				fmt.Fprintf(&b, "    source=%s status=%s subStatus=%s severity=%s\n",
					source.SourceID, source.Status, source.SubStatus, source.Severity)
			}
		}
		b.WriteByte('\n')
	}
	if len(result.IdentityMismatches) > 0 {
		b.WriteString("Identity mismatches (not compared as same objects)\n")
		for _, mismatch := range result.IdentityMismatches {
			fmt.Fprintf(&b, "  [%s] layer=%s: %s\n", mismatch.Category, mismatch.Layer, mismatch.Reason)
		}
		b.WriteByte('\n')
	}
	if len(result.Warnings) > 0 {
		b.WriteString("Warnings\n")
		for _, warning := range result.Warnings {
			fmt.Fprintf(&b, "  - %s\n", warning)
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func writePrettyChanges(b *strings.Builder, title string, changes []ControlChange) {
	if len(changes) == 0 {
		return
	}
	fmt.Fprintf(b, "%s (%d)\n", title, len(changes))
	for _, change := range changes {
		fmt.Fprintf(b, "  - severity=%s resource=%s control=%s rule=%s evidence=%s path=%s",
			change.Severity, change.ResourceID, change.ControlID, change.RuleName,
			change.EvidenceType, change.Path)
		if change.Reason != "" {
			fmt.Fprintf(b, " reason=%q", change.Reason)
		}
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
}
