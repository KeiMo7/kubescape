package core

import (
	"fmt"
	"io"
	"os"
	"strings"

	metav1 "github.com/kubescape/kubescape/v4/core/meta/datastructures/v1"
	resultsdiff "github.com/kubescape/kubescape/v4/core/pkg/resultshandling/diff"
	"github.com/kubescape/kubescape/v4/core/pkg/resultshandling/printer"
)

func effectiveReportGroups(diffInfo *metav1.DiffInfo) (base, head []string, multi bool) {
	if diffInfo == nil || (len(diffInfo.BaseReports) == 0 && len(diffInfo.HeadReports) == 0) {
		return nil, nil, false
	}
	base = append([]string{}, diffInfo.BaseReports...)
	head = append([]string{}, diffInfo.HeadReports...)
	if len(base) == 0 && strings.TrimSpace(diffInfo.BaseFile) != "" {
		base = []string{diffInfo.BaseFile}
	}
	if len(head) == 0 && strings.TrimSpace(diffInfo.HeadFile) != "" {
		head = []string{diffInfo.HeadFile}
	}
	return base, head, true
}

func (ks *Kubescape) diffReportSets(diffInfo *metav1.DiffInfo, basePaths, headPaths []string) (int, error) {
	if strings.TrimSpace(diffInfo.MergedBaseOutput) != "" {
		if err := validateMergedOutputSafety(diffInfo.MergedBaseOutput, basePaths...); err != nil {
			return 0, err
		}
		if err := resultsdiff.WriteMergedReportSet(basePaths, diffInfo.MergedBaseOutput); err != nil {
			return 0, err
		}
	}
	if strings.TrimSpace(diffInfo.MergedHeadOutput) != "" {
		if err := validateMergedOutputSafety(diffInfo.MergedHeadOutput, headPaths...); err != nil {
			return 0, err
		}
		if err := resultsdiff.WriteMergedReportSet(headPaths, diffInfo.MergedHeadOutput); err != nil {
			return 0, err
		}
	}

	multi, err := resultsdiff.CompareReportSets(basePaths, headPaths, resultsdiff.Options{
		Granularity: resultsdiff.Granularity(diffInfo.Granularity),
	})
	if err != nil {
		return 0, err
	}

	var w io.Writer = os.Stdout
	if diffInfo.Writer != nil {
		w = diffInfo.Writer
	}
	if outputFile, explicit := diffOutputPath(diffInfo.Format, diffInfo.Output); explicit {
		f, fileErr := printer.GetWriterNoFallback(outputFile)
		if fileErr != nil {
			return 0, fmt.Errorf("opening diff output: %w", fileErr)
		}
		w = f
		defer func() {
			err = closeDiffOutput(f, err)
		}()
	}

	switch diffInfo.Format {
	case resultsdiff.SummaryJSONFormat:
		err = resultsdiff.PrintSummaryJSON(w, &multi.ChangeSet, diffInfo.SeverityThreshold)
	case resultsdiff.SummaryYAMLFormat:
		err = resultsdiff.PrintSummaryYAML(w, &multi.ChangeSet, diffInfo.SeverityThreshold)
	case resultsdiff.SummaryCSVFormat:
		err = resultsdiff.PrintSummaryCSV(w, &multi.ChangeSet, diffInfo.SeverityThreshold)
	case printer.JsonFormat:
		err = resultsdiff.PrintMultiJSON(w, multi)
	case printer.YamlFormat:
		err = resultsdiff.PrintMultiYAML(w, multi)
	case printer.SARIFFormat:
		err = resultsdiff.PrintSARIF(w, &multi.ChangeSet, diffInfo.SeverityThreshold)
	case printer.JunitResultFormat:
		err = resultsdiff.PrintJUnit(w, &multi.ChangeSet, diffInfo.SeverityThreshold)
	case printer.GitLabSASTFormat:
		err = resultsdiff.PrintGitLabSAST(w, &multi.ChangeSet, diffInfo.SeverityThreshold)
	case printer.MarkdownFormat:
		err = resultsdiff.PrintMarkdown(w, &multi.ChangeSet, diffInfo.SeverityThreshold)
	default:
		err = resultsdiff.PrintMultiPretty(w, multi)
	}
	if err != nil {
		return 0, err
	}
	return multi.GateFailureCount(diffInfo.SeverityThreshold), nil
}

func validateMergedOutputSafety(outputFile string, inputPaths ...string) error {
	if strings.TrimSpace(outputFile) == "" {
		return nil
	}
	destinationInfo, err := os.Stat(outputFile)
	if err != nil {
		// A non-existent destination cannot overwrite an input. Open/write
		// errors are left to WriteMergedReportSet.
		return nil
	}
	for _, inputPath := range inputPaths {
		if strings.TrimSpace(inputPath) == "" {
			continue
		}
		inputInfo, err := os.Stat(inputPath)
		if err != nil {
			continue
		}
		if os.SameFile(destinationInfo, inputInfo) {
			return fmt.Errorf("merged report output %q would overwrite input report %q; choose a different output path", outputFile, inputPath)
		}
	}
	return nil
}
