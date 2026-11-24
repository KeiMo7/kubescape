package auditlog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// behaviorTitles are human-readable rule names for the five behaviors.
var behaviorTitles = map[string]string{
	BehaviorBulkSensitiveRead:  "Bulk read of sensitive objects",
	BehaviorPrivilegedWorkload: "Privileged or host-path workload created",
	BehaviorPrivilegedBinding:  "High-privilege role bound to normal subject",
	BehaviorExecIntoContainer:  "Interactive command executed in container",
	BehaviorAnonymousAccess:    "Successful anonymous (unauthenticated) access",
}

// behaviorOrder fixes rule ordering in SARIF output for determinism.
var behaviorOrder = []string{
	BehaviorBulkSensitiveRead,
	BehaviorPrivilegedWorkload,
	BehaviorPrivilegedBinding,
	BehaviorExecIntoContainer,
	BehaviorAnonymousAccess,
}

// WriteJSON renders the report as indented JSON. encoding/json sorts map
// keys and findings are pre-sorted, so the output is byte-stable for
// identical input.
func WriteJSON(w io.Writer, rep *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// WriteSARIF renders the report as a SARIF 2.1.0 log: one rule per behavior,
// one result per finding. Only identifiers and counts appear in messages.
func WriteSARIF(w io.Writer, rep *Report) error {
	run := sarif.NewRunWithInformationURI("kubescape", "https://kubescape.io/")
	for _, b := range behaviorOrder {
		run.AddRule(b).
			WithName(behaviorTitles[b]).
			WithFullDescription(sarif.NewMultiformatMessageString(
				fmt.Sprintf("Kubernetes audit-log behavioral detection: %s.", behaviorTitles[b])))
	}
	for _, f := range rep.Findings {
		msg := fmt.Sprintf("%s: subject %q touched %d object(s) (%d events) between %s and %s (window %s..%s).",
			behaviorTitles[f.Behavior], f.Subject, f.Count, f.Events,
			f.FirstSeen, f.LastSeen, f.Window.Start, f.Window.End)
		result := sarif.NewRuleResult(f.Behavior).
			WithMessage(sarif.NewTextMessage(msg)).
			WithLevel("warning")
		// One SARIF location per involved object identifier (already capped
		// by maxObjectsPerFinding in the finding itself).
		var locs []*sarif.Location
		for _, obj := range f.Objects {
			locs = append(locs, sarif.NewLocation().
				WithLogicalLocations([]*sarif.LogicalLocation{
					sarif.NewLogicalLocation().WithFullyQualifiedName(obj),
				}))
		}
		if len(locs) > 0 {
			result.WithLocations(locs)
		}
		run.AddResult(result)
	}
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}
	report.AddRun(run)
	return report.Write(w)
}

// WritePretty renders a deterministic plain-text table for humans.
func WritePretty(w io.Writer, rep *Report) error {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Audit behavior report (%s)\n", rep.Summary.Status)
	fmt.Fprintf(&buf, "Files: %d  Events parsed: %d  Succeeded: %d  Invalid lines: %d  Findings: %d\n",
		rep.Summary.FilesScanned, rep.Summary.EventsParsed, rep.Summary.EventsSucceeded,
		rep.Summary.InvalidLines, rep.Summary.FindingsTotal)
	if rep.Summary.Window.ObservedStart != "" {
		fmt.Fprintf(&buf, "Observed window: %s .. %s (tumbling %ds windows, epoch-aligned, UTC)\n",
			rep.Summary.Window.ObservedStart, rep.Summary.Window.ObservedEnd, rep.Summary.Window.WindowSeconds)
	}
	for _, warn := range rep.Summary.Warnings {
		fmt.Fprintf(&buf, "WARNING: %s\n", warn)
	}
	for _, reason := range rep.Summary.PartialReason {
		fmt.Fprintf(&buf, "PARTIAL: %s\n", reason)
	}
	if len(rep.Findings) > 0 {
		fmt.Fprintln(&buf)
		tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "BEHAVIOR\tSUBJECT\tCOUNT\tEVENTS\tFIRST SEEN\tLAST SEEN")
		for _, f := range rep.Findings {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n",
				f.Behavior, f.Subject, f.Count, f.Events, f.FirstSeen, f.LastSeen)
		}
		tw.Flush()
		fmt.Fprintln(&buf)
		// Object identifiers for review, sorted per finding.
		for _, f := range rep.Findings {
			fmt.Fprintf(&buf, "- %s / %s (window %s):\n", f.Behavior, f.Subject, f.Window.Start)
			objs := append([]string(nil), f.Objects...)
			sort.Strings(objs)
			for _, o := range objs {
				fmt.Fprintf(&buf, "    %s\n", o)
			}
			if f.ObjectsTruncated {
				fmt.Fprintf(&buf, "    ... (%d total objects)\n", f.ObjectsTotal)
			}
		}
	}
	_, err := w.Write(buf.Bytes())
	return err
}
