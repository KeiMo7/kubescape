package diff

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/kubescape/kubescape/v4/cmd/shared"
	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/meta"
	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	resultsdiff "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
	"github.com/spf13/cobra"
)

var diffCmdExamples = fmt.Sprintf(`
  Diff command compares two Kubescape scan JSON reports and shows what changed.

  # Scan base branch, then the PR branch, then compare
  1) %[1]s scan --format json --output base.json .
  2) (make your changes)
  3) %[1]s scan --format json --output head.json .
  4) %[1]s diff base.json head.json

	# Fail CI when new high-severity or above failures are introduced
	%[1]s diff base.json head.json --fail-on-new --severity-threshold high

	# Compare resource-and-control aggregates while keeping safety checks
	%[1]s diff base.json head.json --granularity control

  # Output only new and incomparable regressions as SARIF for GitHub Code Scanning
  %[1]s diff base.json head.json --format sarif --output kubescape-diff

  # Output diff as JSON
  %[1]s diff base.json head.json --format json --output diff.json

  # Compare one baseline report against a group of framework-split reports
  %[1]s diff --base-report baseline.json --head-report nsa.json --head-report mitre.json --format json

  # Compare groups on both sides and write deterministic merged posture reports
  %[1]s diff --base-report base-nsa.json --base-report base-mitre.json --head-report head-nsa.json --head-report head-mitre.json --merge-base-output base-merged.json --merge-head-output head-merged.json

  # Output aggregate diff counts for dashboards and CI annotations
  %[1]s diff base.json head.json --format summary-json --output diff-summary.json

  # Output aggregate diff counts as CSV for spreadsheet-friendly artifacts
  %[1]s diff base.json head.json --format summary-csv --output diff-summary.csv

  # Compare two image scans and fail when an upgrade introduces high or critical CVEs
  1) %[1]s scan image nginx:1.26 --format json --output base-image.json
  2) %[1]s scan image nginx:1.27 --format json --output head-image.json
  3) %[1]s diff base-image.json head-image.json --fail-on-new --severity-threshold high
`, cautils.ExecName())

func GetDiffCmd(ks meta.IKubescape) *cobra.Command {
	var diffInfo metav1.DiffInfo

	diffCmd := &cobra.Command{
		Use:   "diff <base-report.json> <head-report.json> [additional-head-reports...]",
		Short: "Compare two Kubescape scan JSON reports or framework report groups and show what changed",
		Long: `Compare a base scan report against a head scan report to surface new failures, resolved issues, unchanged evidence, and results that cannot be compared safely. By default, failed rules and paths are compared so regressions inside an already-failing control are detected.

Image scan reports ("scan image --format json") are compared by vulnerability instead: a CVE is identified by its ID, package and package type, so upgrading a package that still carries the same CVE counts as unchanged. Findings from a multi-image report are pooled across all its images, so --fail-on-new does not flag a CVE that spreads to another image when any base image already had it. Image reports support the pretty-printer, json, yaml, markdown, junit, sarif, summary-json, summary-yaml and summary-csv formats; markdown, junit and sarif list the new vulnerabilities that meet --severity-threshold, the summary formats count new, resolved and unchanged vulnerabilities by severity and package, and both reports must be of the same kind.`,
		Example: diffCmdExamples,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 2 {
				if strings.TrimSpace(args[0]) == "" {
					return errors.New("base report file path cannot be empty")
				}
				if strings.TrimSpace(args[1]) == "" {
					return errors.New("head report file path cannot be empty")
				}
				return nil
			}
			if len(args) > 2 {
				for i, arg := range args {
					if strings.TrimSpace(arg) == "" {
						return fmt.Errorf("report path at argument %d cannot be empty", i+1)
					}
				}
				return nil
			}
			if len(args) == 0 && reportSetFlagsProvided(cmd) {
				return nil
			}
			return fmt.Errorf("accepts 2 arg(s), received %d", len(args))
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if ks == nil {
				return errors.New("uninitialized kubescape interface")
			}
			groupFlags := reportSetFlagsProvided(cmd)
			if !groupFlags && len(args) == 2 {
				if strings.TrimSpace(args[0]) == "" {
					return errors.New("base report file path cannot be empty")
				}
				if strings.TrimSpace(args[1]) == "" {
					return errors.New("head report file path cannot be empty")
				}
			}
			if groupFlags && len(args) == 0 && len(diffInfo.BaseReports) == 0 && len(diffInfo.HeadReports) == 0 {
				return errors.New("report-set flags were provided without any report paths")
			}
			if len(args) >= 1 && strings.TrimSpace(args[0]) == "" {
				return errors.New("base report file path cannot be empty")
			}
			if len(args) >= 2 && strings.TrimSpace(args[1]) == "" {
				return errors.New("head report file path cannot be empty")
			}
			if len(args) == 0 && !groupFlags {
				return errors.New("base report file path cannot be empty")
			}
			if len(args) == 1 && !groupFlags {
				return errors.New("head report file path cannot be empty")
			}

			configureReportGroups(&diffInfo, args, groupFlags)
			if diffInfo.BaseFile == "" && len(diffInfo.BaseReports) > 0 {
				diffInfo.BaseFile = diffInfo.BaseReports[0]
			}
			if diffInfo.HeadFile == "" && len(diffInfo.HeadReports) > 0 {
				diffInfo.HeadFile = diffInfo.HeadReports[0]
			}
			diffInfo.Writer = cmd.OutOrStdout()

			// diff honors a single output format, so validate against the exact value rather than scan's comma-separated multi-format set.
			supportedFormats := diffFormats()
			trimmedFormat := strings.ToLower(strings.TrimSpace(diffInfo.Format))
			if trimmedFormat == "" {
				return fmt.Errorf("format cannot be empty, supported formats: %s", strings.Join(supportedFormats, ", "))
			}
			if !slices.Contains(supportedFormats, trimmedFormat) {
				return fmt.Errorf("invalid format %q, supported formats: %s", diffInfo.Format, strings.Join(supportedFormats, ", "))
			}
			diffInfo.Format = trimmedFormat

			if diffInfo.SeverityThreshold != "" {
				if err := shared.ValidateSeverity(diffInfo.SeverityThreshold); err != nil {
					return err
				}
				diffInfo.SeverityThreshold = strings.ToLower(strings.TrimSpace(diffInfo.SeverityThreshold))
			}
			if err := resultsdiff.ValidateGranularity(diffInfo.Granularity); err != nil {
				return err
			}

			if cmd.Flags().Changed("output") {
				trimmedOutput := strings.TrimSpace(diffInfo.Output)
				if trimmedOutput == "" {
					return errors.New("output file path cannot be empty")
				}
				diffInfo.Output = trimmedOutput
			}

			// The invocation is valid from this point on. Runtime and result-gate
			// failures should not print command usage.
			cmd.SilenceUsage = true

			newFailures, err := ks.Diff(&diffInfo)
			if err != nil {
				return err
			}

			if diffInfo.FailOnNew && newFailures > 0 {
				findings := "new or incomparable failure(s)"
				if isVulnerabilityDiff(diffInfo.BaseFile, diffInfo.HeadFile) {
					findings = "new vulnerability(ies)"
				}
				return fmt.Errorf("found %d %s at or above severity threshold %q",
					newFailures, findings, severityLabel(diffInfo.SeverityThreshold))
			}

			return nil
		},
	}

	diffCmd.Flags().BoolVar(&diffInfo.FailOnNew, "fail-on-new", false, "Exit with code 1 when new or incomparable failures, or new vulnerabilities for image reports, are found (combine with --severity-threshold to limit the gate)")
	diffCmd.Flags().StringVar(&diffInfo.SeverityThreshold, "severity-threshold", "", "Only count new and incomparable failures at or above this severity when using --fail-on-new (low, medium, high, critical)")
	diffCmd.Flags().StringVarP(&diffInfo.Format, "format", "f", "pretty-printer", fmt.Sprintf(`Output format: "%s"`, strings.Join(diffFormats(), `", "`)))
	diffCmd.Flags().StringVarP(&diffInfo.Output, "output", "o", "", "Output file; defaults to stdout")
	diffCmd.Flags().StringVar(&diffInfo.Granularity, "granularity", string(resultsdiff.GranularityEvidence), `Comparison unit for posture reports: "evidence" or "control"`)

	diffCmd.Flags().StringArrayVar(&diffInfo.BaseReports, "base-report", nil, "Base-side posture report; repeat or use comma-separated paths to merge framework-split reports")
	diffCmd.Flags().StringArrayVar(&diffInfo.BaseReports, "base-reports", nil, "Alias for --base-report")
	diffCmd.Flags().StringArrayVar(&diffInfo.BaseReports, "base", nil, "Alias for --base-report")
	diffCmd.Flags().StringArrayVar(&diffInfo.BaseReports, "baseline-report", nil, "Alias for --base-report")
	diffCmd.Flags().StringArrayVar(&diffInfo.BaseReports, "baseline-reports", nil, "Alias for --base-report")
	diffCmd.Flags().StringArrayVar(&diffInfo.HeadReports, "head-report", nil, "Head-side posture report; repeat or use comma-separated paths to merge framework-split reports")
	diffCmd.Flags().StringArrayVar(&diffInfo.HeadReports, "head-reports", nil, "Alias for --head-report")
	diffCmd.Flags().StringArrayVar(&diffInfo.HeadReports, "head", nil, "Alias for --head-report")
	diffCmd.Flags().StringArrayVar(&diffInfo.HeadReports, "current-report", nil, "Alias for --head-report")
	diffCmd.Flags().StringArrayVar(&diffInfo.HeadReports, "current-reports", nil, "Alias for --head-report")
	diffCmd.Flags().StringVar(&diffInfo.MergedBaseOutput, "merge-base-output", "", "Write the deterministic merged base report JSON to this path before comparison")
	diffCmd.Flags().StringVar(&diffInfo.MergedBaseOutput, "merge-base", "", "Alias for --merge-base-output")
	diffCmd.Flags().StringVar(&diffInfo.MergedHeadOutput, "merge-head-output", "", "Write the deterministic merged head report JSON to this path before comparison")
	diffCmd.Flags().StringVar(&diffInfo.MergedHeadOutput, "merge-head", "", "Alias for --merge-head-output")

	return diffCmd
}

func reportSetFlagsProvided(cmd *cobra.Command) bool {
	names := []string{
		"base-report", "base-reports", "base", "baseline-report", "baseline-reports",
		"head-report", "head-reports", "head", "current-report", "current-reports",
		"merge-base-output", "merge-base", "merge-head-output", "merge-head",
	}
	for _, name := range names {
		if flag := cmd.Flags().Lookup(name); flag != nil && flag.Changed {
			return true
		}
	}
	return false
}

func configureReportGroups(diffInfo *metav1.DiffInfo, args []string, groupFlags bool) {
	diffInfo.BaseReports = normalizeReportPathValues(diffInfo.BaseReports)
	diffInfo.HeadReports = normalizeReportPathValues(diffInfo.HeadReports)
	hasGroupFlags := groupFlags || len(diffInfo.BaseReports) > 0 || len(diffInfo.HeadReports) > 0 ||
		strings.TrimSpace(diffInfo.MergedBaseOutput) != "" || strings.TrimSpace(diffInfo.MergedHeadOutput) != ""
	if len(args) == 0 {
		return
	}
	diffInfo.BaseFile = args[0]
	if len(args) >= 2 {
		diffInfo.HeadFile = args[1]
	}
	if len(args) > 2 {
		base := append([]string{args[0]}, diffInfo.BaseReports...)
		head := append(append([]string{}, diffInfo.HeadReports...), args[1:]...)
		diffInfo.BaseReports = base
		diffInfo.HeadReports = head
		return
	}
	if hasGroupFlags {
		if len(diffInfo.BaseReports) == 0 {
			diffInfo.BaseReports = []string{args[0]}
		}
		if len(diffInfo.HeadReports) == 0 && len(args) == 2 {
			diffInfo.HeadReports = []string{args[1]}
		}
		return
	}
	// Preserve the exact single-report path when no report-set flags are used.
	diffInfo.BaseReports = nil
	diffInfo.HeadReports = nil
}

func normalizeReportPathValues(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			result = append(result, strings.TrimSpace(part))
		}
	}
	return result
}

func isVulnerabilityDiff(base, head string) bool {
	return resultsdiff.ReportKindOf(base) == resultsdiff.VulnerabilityReport ||
		resultsdiff.ReportKindOf(head) == resultsdiff.VulnerabilityReport
}

func severityLabel(s string) string {
	if s == "" {
		return "all"
	}
	return s
}

func diffFormats() []string {
	return []string{
		printer.PrettyFormat,
		resultsdiff.SummaryJSONFormat,
		resultsdiff.SummaryYAMLFormat,
		resultsdiff.SummaryCSVFormat,
		printer.JsonFormat,
		printer.YamlFormat,
		printer.SARIFFormat,
		printer.JunitResultFormat,
		printer.GitLabSASTFormat,
		printer.MarkdownFormat,
	}
}
