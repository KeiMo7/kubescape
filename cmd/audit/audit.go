package audit

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kubescape/kubescape/v4/core/cautils"
	"github.com/kubescape/kubescape/v4/core/pkg/auditlog"
	"github.com/spf13/cobra"
)

var auditExample = fmt.Sprintf(`
  # Analyze a Kubernetes API audit-log export (newline-delimited JSON)
  %[1]s audit /var/log/kubernetes/audit.log

  # Analyze several exports at once, including archives (.gz, .zip, .tar, .tar.gz)
  %[1]s audit audit-part1.jsonl.gz audit-part2.zip --output audit-report.json

  # Tune detection thresholds
  %[1]s audit audit.log --window 5m --bulk-read-threshold 10

  # Emit SARIF for code-scanning pipelines
  %[1]s audit audit.log --format sarif --output audit-report.sarif
`, cautils.ExecName())

// GetAuditCmd builds the `kubescape audit` command. It works fully offline:
// no cluster credentials are ever required.
func GetAuditCmd() *cobra.Command {
	var (
		format            string
		output            string
		configPath        string
		window            string
		bulkReadThreshold int
		sensitiveRes      []string
		privilegedRoles   []string
		platformSubjects  []string
		execSubresources  []string
		maxObjects        int
	)

	cmd := &cobra.Command{
		Use:     "audit <audit-log-file> [more files...]",
		Short:   "Analyze Kubernetes API audit-log exports for suspicious behavior over time",
		Example: auditExample,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := auditlog.LoadConfig(configPath)
			if err != nil {
				return err
			}
			flags := cmd.Flags()
			if flags.Changed("window") {
				d, err := parseWindow(window)
				if err != nil {
					return err
				}
				cfg.WindowSeconds = d
			}
			if flags.Changed("bulk-read-threshold") {
				cfg.BulkReadThreshold = bulkReadThreshold
			}
			if flags.Changed("sensitive-resources") {
				cfg.SensitiveResources = sensitiveRes
			}
			if flags.Changed("privileged-roles") {
				cfg.PrivilegedRoles = privilegedRoles
			}
			if flags.Changed("platform-subjects") {
				cfg.PlatformSubjects = platformSubjects
			}
			if flags.Changed("exec-subresources") {
				cfg.ExecSubresources = execSubresources
			}
			if flags.Changed("max-objects") {
				cfg.MaxObjectsPerFinding = maxObjects
			}

			analyzer, err := auditlog.NewAnalyzer(cfg)
			if err != nil {
				return err
			}
			rep, err := analyzer.Run(args)
			if err != nil {
				return err
			}

			if err := writeReport(cmd, rep, format, output); err != nil {
				return err
			}
			if rep.Summary.Status == "partial" {
				return fmt.Errorf("audit incomplete: some inputs could not be fully read (see report summary.partialReason)")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&format, "format", "json", "output format: json, sarif, pretty")
	cmd.Flags().StringVarP(&output, "output", "o", "", "output file (default: stdout)")
	cmd.Flags().StringVar(&configPath, "config", "", "YAML/JSON config file with detection thresholds")
	cmd.Flags().StringVar(&window, "window", "", "aggregation window, e.g. 10m, 1h (default 10m)")
	cmd.Flags().IntVar(&bulkReadThreshold, "bulk-read-threshold", 0, "distinct sensitive objects read within one window to flag (default 20)")
	cmd.Flags().StringSliceVar(&sensitiveRes, "sensitive-resources", nil, "comma-separated sensitive resources (default: secrets)")
	cmd.Flags().StringSliceVar(&privilegedRoles, "privileged-roles", nil, "comma-separated high-privilege role names (default: cluster-admin)")
	cmd.Flags().StringSliceVar(&platformSubjects, "platform-subjects", nil, "comma-separated subject prefixes treated as platform identities")
	cmd.Flags().StringSliceVar(&execSubresources, "exec-subresources", nil, "comma-separated pod subresources treated as container entry (default: exec,attach)")
	cmd.Flags().IntVar(&maxObjects, "max-objects", -1, "max object identifiers embedded per finding (default 100)")
	return cmd
}

func parseWindow(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("window must not be empty")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --window %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid --window %q: must be > 0", s)
	}
	return int64(d.Seconds()), nil
}

func writeReport(cmd *cobra.Command, rep *auditlog.Report, format, output string) error {
	w := cmd.OutOrStdout()
	if output != "" {
		f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return fmt.Errorf("opening output file %q: %w", output, err)
		}
		defer f.Close()
		w = f
	}
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return auditlog.WriteJSON(w, rep)
	case "sarif":
		return auditlog.WriteSARIF(w, rep)
	case "pretty":
		return auditlog.WritePretty(w, rep)
	default:
		return fmt.Errorf("unsupported --format %q: use json, sarif or pretty", format)
	}
}
