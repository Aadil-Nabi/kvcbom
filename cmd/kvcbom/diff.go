package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Aadil-Nabi/kvcbom/internal/cli"
	"github.com/Aadil-Nabi/kvcbom/internal/safety"
	"github.com/Aadil-Nabi/kvcbom/pkg/diff"
	"github.com/Aadil-Nabi/kvcbom/pkg/report"
	jsonrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/json"
)

const maxReportBytes int64 = 64 << 20

func newDiffCmd() *cobra.Command {
	var (
		baseline         string
		current          string
		formats          []string
		outDir           string
		failOnRegression bool
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two report JSON files and show what changed",
		Long: "diff compares two canonical report.json files and reports assets added,\n" +
			"removed, or changed and findings opened or resolved, so progress between\n" +
			"assessments can be tracked. With --fail-on-regression it exits 3 when risk rose.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if baseline == "" || current == "" {
				return cli.Codedf(cli.ExitUsage, "both --baseline and --current are required")
			}

			base, err := loadReport(baseline)
			if err != nil {
				return cli.Coded(cli.ExitValidation, err)
			}
			cur, err := loadReport(current)
			if err != nil {
				return cli.Coded(cli.ExitValidation, err)
			}

			res := diff.Compare(base, cur)

			if outDir == "" {
				// Print the first requested format to stdout.
				data, err := renderDiff(firstFormat(formats), res)
				if err != nil {
					return err
				}
				cmd.OutOrStdout().Write(data)
			} else {
				written, err := writeDiffFormats(outDir, formats, res)
				if err != nil {
					return err
				}
				for _, f := range written {
					cmd.PrintErrln("wrote", f)
				}
			}

			if failOnRegression {
				regressed := countRegressed(res)
				// New findings also count as a regression for CI purposes.
				if regressed+res.Summary.FindingsAdded > 0 {
					return cli.Codedf(cli.ExitPolicy,
						"risk regressed: %d asset regression(s) and %d new finding(s)",
						regressed, res.Summary.FindingsAdded)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&baseline, "baseline", "", "path to the baseline report.json (required)")
	cmd.Flags().StringVar(&current, "current", "", "path to the current report.json (required)")
	cmd.Flags().StringSliceVar(&formats, "format", []string{"md"}, "output formats: json,md")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory; prints to stdout when omitted")
	cmd.Flags().BoolVar(&failOnRegression, "fail-on-regression", false, "exit code 3 if risk rose or new findings appeared")
	return cmd
}

func loadReport(path string) (*report.Report, error) {
	data, err := safety.ReadFileLimited(path, maxReportBytes)
	if err != nil {
		return nil, err
	}
	r, err := jsonrender.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

func renderDiff(format string, res *diff.Result) ([]byte, error) {
	switch format {
	case "json":
		b, err := json.MarshalIndent(res, "", "  ")
		if err != nil {
			return nil, cli.Coded(cli.ExitInternal, err)
		}
		return append(b, '\n'), nil
	case "md", "markdown":
		return []byte(diff.Markdown(res)), nil
	default:
		return nil, cli.Codedf(cli.ExitUsage, "unknown format %q (want json, md)", format)
	}
}

func writeDiffFormats(dir string, formats []string, res *diff.Result) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, cli.Coded(cli.ExitInternal, err)
	}
	want := map[string]struct{}{}
	for _, f := range formats {
		want[strings.ToLower(strings.TrimSpace(f))] = struct{}{}
	}
	names := make([]string, 0, len(want))
	for f := range want {
		names = append(names, f)
	}
	sort.Strings(names)

	var written []string
	for _, f := range names {
		data, err := renderDiff(f, res)
		if err != nil {
			return written, err
		}
		name := "diff." + ext(f)
		dest, ok := safety.WithinBase(dir, name)
		if !ok {
			return written, cli.Codedf(cli.ExitInternal, "refusing to write outside %s", dir)
		}
		if err := os.WriteFile(dest, data, 0o640); err != nil {
			return written, cli.Coded(cli.ExitInternal, err)
		}
		written = append(written, filepath.Join(dir, name))
	}
	return written, nil
}

func ext(format string) string {
	if format == "md" || format == "markdown" {
		return "md"
	}
	return "json"
}

func firstFormat(formats []string) string {
	if len(formats) == 0 {
		return "md"
	}
	return strings.ToLower(strings.TrimSpace(formats[0]))
}

func countRegressed(res *diff.Result) int {
	n := 0
	for _, c := range res.AssetsChanged {
		if c.Regressed {
			n++
		}
	}
	return n
}
