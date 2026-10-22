package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Aadil-Nabi/kvcbom/internal/cli"
	"github.com/Aadil-Nabi/kvcbom/internal/safety"
	"github.com/Aadil-Nabi/kvcbom/internal/version"
	"github.com/Aadil-Nabi/kvcbom/pkg/ingest/cbom"
	ctxingest "github.com/Aadil-Nabi/kvcbom/pkg/ingest/context"
	"github.com/Aadil-Nabi/kvcbom/pkg/ingest/register"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/pkg/report"
	htmlrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/html"
	jsonrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/json"
	mdrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/md"
	pdfrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/pdf"
	"github.com/Aadil-Nabi/kvcbom/pkg/rulepack"
)

func newReportCmd() *cobra.Command {
	var (
		cbomFiles    []string
		registerFile string
		mappingFile  string
		contextFile  string
		packRef      string
		frameworks   []string
		formats      []string
		outDir       string
		title        string
		org          string
		timestamp    string
		force        bool
		failOn       string
		pdfEngine    string
		cbomMapping  string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Run the full assessment and write a report in one or more formats",
		Long: "report ingests CBOMs (and an optional register and context), classifies and\n" +
			"scores the inventory with the selected rule pack, maps findings onto any\n" +
			"framework overlays, and writes the canonical JSON plus any requested\n" +
			"HTML/Markdown/PDF into --out. It makes no network calls.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// A --config profile fills any flag the user did not set explicitly
			// (precedence: flags > config > defaults). With no --config, a kvcbom.yaml in
			// the current directory is auto-loaded. Paths in the file resolve relative to
			// the file itself, so a profile is portable.
			cfgPath, _ := cmd.Flags().GetString("config")
			if cfgPath == "" {
				if p := findDefaultConfig(); p != "" {
					cfgPath = p
					cmd.PrintErrln("using config", p)
				}
			}
			if cfgPath != "" {
				cfg, dir, err := loadReportConfig(cfgPath)
				if err != nil {
					return err
				}
				unset := func(name string) bool { return !cmd.Flags().Changed(name) }
				if unset("cbom") && len(cfg.CBOM) > 0 {
					cbomFiles = nil
					for _, p := range cfg.CBOM {
						cbomFiles = append(cbomFiles, resolveUnder(dir, p))
					}
				}
				if unset("register") && cfg.Register != "" {
					registerFile = resolveUnder(dir, cfg.Register)
				}
				if unset("register-mapping") && cfg.RegisterMapping != "" {
					mappingFile = resolveUnder(dir, cfg.RegisterMapping)
				}
				if unset("context") && cfg.Context != "" {
					contextFile = resolveUnder(dir, cfg.Context)
				}
				if unset("cbom-mapping") && cfg.CBOMMapping != "" {
					cbomMapping = resolveUnder(dir, cfg.CBOMMapping)
				}
				if unset("out") && cfg.Out != "" {
					outDir = resolveUnder(dir, cfg.Out)
				}
				// Rule-pack refs are embedded ids or user-managed paths, not resolved.
				if unset("rulepack") && cfg.Rulepack != "" {
					packRef = cfg.Rulepack
				}
				if unset("framework") && len(cfg.Framework) > 0 {
					frameworks = cfg.Framework
				}
				if unset("format") && len(cfg.Format) > 0 {
					formats = cfg.Format
				}
				if unset("title") && cfg.Title != "" {
					title = cfg.Title
				}
				if unset("org") && cfg.Org != "" {
					org = cfg.Org
				}
				if unset("timestamp") && cfg.Timestamp != "" {
					timestamp = cfg.Timestamp
				}
				if unset("fail-on") && cfg.FailOn != "" {
					failOn = cfg.FailOn
				}
				if unset("pdf-engine") && cfg.PDFEngine != "" {
					pdfEngine = cfg.PDFEngine
				}
				if unset("force") && cfg.Force != nil {
					force = *cfg.Force
				}
			}

			if len(cbomFiles) == 0 && registerFile == "" {
				return cli.Codedf(cli.ExitUsage, "at least one --cbom or a --register is required")
			}
			if outDir == "" {
				return cli.Codedf(cli.ExitUsage, "--out <dir> is required")
			}
			if packRef == "" {
				packRef = "baseline-pqc"
			}

			ts, err := resolveTimestamp(timestamp)
			if err != nil {
				return cli.Coded(cli.ExitUsage, err)
			}

			// Load the rule pack and refuse to run on a pack with errors.
			lp, err := rulepack.Load(packRef)
			if err != nil {
				return cli.Coded(cli.ExitValidation, err)
			}
			if err := rulepack.ValidationError(lp.Pack.Validate()); err != nil {
				return cli.Coded(cli.ExitValidation, err)
			}
			if len(lp.Pack.ClassificationEntries()) == 0 {
				return cli.Codedf(cli.ExitUsage,
					"rule pack %q has no classification table (it is a framework overlay); "+
						"pass it via --framework alongside a classifier such as baseline-pqc", packRef)
			}

			// Load framework overlay packs (national regulators etc.); their control mappings
			// are applied to the findings produced by the classifier pack above.
			var overlays []*rulepack.Pack
			for _, fref := range frameworks {
				flp, err := rulepack.Load(fref)
				if err != nil {
					return cli.Coded(cli.ExitValidation, err)
				}
				if err := rulepack.ValidationError(flp.Pack.Validate()); err != nil {
					return cli.Coded(cli.ExitValidation, err)
				}
				overlays = append(overlays, flp.Pack)
			}

			var cbomMap *cbom.Mapping
			if cbomMapping != "" {
				cbomMap, err = cbom.LoadMapping(cbomMapping)
				if err != nil {
					return cli.Coded(cli.ExitValidation, err)
				}
			}

			var batches []*model.Batch
			var ingestWarnings []string
			for _, path := range cbomFiles {
				res, err := cbom.IngestFile(path, cbom.Options{ValidateSchema: true, Mapping: cbomMap})
				if err != nil {
					// A file that cannot be decoded at all is a hard input failure.
					return cli.Codedf(cli.ExitValidation, "%s: %v", path, err)
				}
				// A schema non-conformance (often a stray CycloneDX 1.7 field in a 1.6 CBOM) is
				// recorded as a warning: the asset data still parses and is worth assessing. Use
				// `validate` for a strict schema gate.
				if res.SchemaError != nil {
					ingestWarnings = append(ingestWarnings,
						fmt.Sprintf("%s did not fully conform to CycloneDX 1.6: %v", path, res.SchemaError))
				}
				batches = append(batches, res.Batch)
			}

			if registerFile != "" {
				var mapping *register.Mapping
				if mappingFile != "" {
					mapping, err = register.LoadMapping(mappingFile)
					if err != nil {
						return cli.Coded(cli.ExitValidation, err)
					}
				}
				res, err := register.IngestFile(registerFile, mapping, register.Options{})
				if err != nil {
					return cli.Coded(cli.ExitValidation, err)
				}
				for _, warn := range res.Warnings {
					cmd.PrintErrln("register:", warn)
					ingestWarnings = append(ingestWarnings, "register: "+warn)
				}
				batches = append(batches, res.Batch)
			}

			var ctx *model.Context
			assessment := model.AssessmentMeta{Organisation: org}
			if contextFile != "" {
				cres, err := ctxingest.LoadFile(contextFile)
				if err != nil {
					return cli.Coded(cli.ExitValidation, err)
				}
				ctx = cres.Context
				assessment = ctx.Meta
				if org != "" {
					assessment.Organisation = org // flag overrides the context value
				}
			}

			rep, err := report.Build(report.Input{
				Title:          title,
				Assessment:     assessment,
				IngestWarnings: ingestWarnings,
				Batches:        batches,
				Context:        ctx,
				Pack:           lp.Pack,
				PackSHA256:     lp.SHA256,
				Overlays:       overlays,
				Tool:           report.ToolInfo{Name: "kvcbom", Version: version.Version, Commit: version.Commit, Date: version.Date},
				GeneratedAt:    ts,
			})
			if err != nil {
				return cli.Coded(cli.ExitInternal, err)
			}

			if err := prepareOutDir(outDir, force); err != nil {
				return err
			}
			written, err := writeFormats(outDir, formats, rep, pdfEngine)
			if err != nil {
				return err
			}
			for _, f := range written {
				cmd.PrintErrln("wrote", f)
			}

			// Policy gate: exit 3 when a finding meets or exceeds the threshold (SPEC §8).
			if failOn != "" {
				threshold, err := parseSeverity(failOn)
				if err != nil {
					return cli.Coded(cli.ExitUsage, err)
				}
				breached := 0
				for _, f := range rep.Findings {
					if f.Severity.Rank() <= threshold.Rank() {
						breached++
					}
				}
				if breached > 0 {
					return cli.Codedf(cli.ExitPolicy,
						"policy threshold --fail-on=%s breached: %d finding(s) at or above %s",
						failOn, breached, failOn)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&cbomFiles, "cbom", nil, "path to a CBOM file (repeatable)")
	cmd.Flags().StringVar(&registerFile, "register", "", "path to a manual register (.xlsx or .csv)")
	cmd.Flags().StringVar(&mappingFile, "register-mapping", "", "path to a register column mapping (YAML); default mapping used otherwise")
	cmd.Flags().StringVar(&contextFile, "context", "", "path to an assessment context file (YAML)")
	cmd.Flags().StringVar(&packRef, "rulepack", "", "classifier rule pack id or path (default: baseline-pqc)")
	cmd.Flags().StringArrayVar(&frameworks, "framework", nil, "framework overlay pack id or path to also map findings onto (repeatable)")
	cmd.Flags().StringSliceVar(&formats, "format", []string{"json"}, "output formats: json,html,md,pdf")
	cmd.Flags().StringVar(&outDir, "out", "", "output directory (required)")
	cmd.Flags().StringVar(&title, "title", "", "report title")
	cmd.Flags().StringVar(&org, "org", "", "organisation name (overrides the context value)")
	cmd.Flags().StringVar(&timestamp, "timestamp", "", "RFC3339 timestamp for reproducible output (else SOURCE_DATE_EPOCH or now)")
	cmd.Flags().BoolVar(&force, "force", false, "write into a non-empty output directory")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit code 3 if any finding is at or above this severity: critical|high|medium|low|info")
	cmd.Flags().StringVar(&pdfEngine, "pdf-engine", "purego", "PDF engine when --format includes pdf: purego (offline) or chromium (needs a local browser)")
	cmd.Flags().StringVar(&cbomMapping, "cbom-mapping", "", "path to a CBOM extension-mapping YAML (maps vendor property keys to the algorithm)")
	return cmd
}

// pdfRenderer returns the PDF engine named by the flag, or an error for an unknown or
// unavailable engine.
func pdfRenderer(engine string) (report.PDFRenderer, error) {
	switch strings.ToLower(strings.TrimSpace(engine)) {
	case "", "purego":
		return pdfrender.PureGo{}, nil
	case "chromium":
		r := pdfrender.Chromium{}
		if ok, msg := r.Available(); !ok {
			return nil, cli.Codedf(cli.ExitUsage, "chromium PDF engine unavailable: %s", msg)
		}
		return r, nil
	default:
		return nil, cli.Codedf(cli.ExitUsage, "unknown --pdf-engine %q (want purego or chromium)", engine)
	}
}

// parseSeverity maps a --fail-on value to a model.Severity.
func parseSeverity(s string) (model.Severity, error) {
	switch sev := model.Severity(strings.ToLower(strings.TrimSpace(s))); sev {
	case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo:
		return sev, nil
	default:
		return "", fmt.Errorf("invalid --fail-on %q (want critical|high|medium|low|info)", s)
	}
}

// resolveTimestamp picks the report timestamp: --timestamp, else SOURCE_DATE_EPOCH, else
// the current time. The result is normalised to UTC RFC3339 for reproducibility.
func resolveTimestamp(flag string) (string, error) {
	if flag != "" {
		t, err := time.Parse(time.RFC3339, flag)
		if err != nil {
			return "", fmt.Errorf("invalid --timestamp %q (want RFC3339): %w", flag, err)
		}
		return t.UTC().Format(time.RFC3339), nil
	}
	if epoch := os.Getenv("SOURCE_DATE_EPOCH"); epoch != "" {
		secs, err := strconv.ParseInt(epoch, 10, 64)
		if err != nil {
			return "", fmt.Errorf("invalid SOURCE_DATE_EPOCH %q: %w", epoch, err)
		}
		return time.Unix(secs, 0).UTC().Format(time.RFC3339), nil
	}
	return time.Now().UTC().Format(time.RFC3339), nil
}

// prepareOutDir creates the output directory, refusing a non-empty one unless force is set.
func prepareOutDir(dir string, force bool) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return cli.Coded(cli.ExitInternal, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return cli.Coded(cli.ExitInternal, err)
	}
	if len(entries) > 0 && !force {
		return cli.Codedf(cli.ExitUsage, "output directory %s is not empty (use --force to overwrite)", dir)
	}
	return nil
}

func writeFormats(dir string, formats []string, rep *report.Report, pdfEngine string) ([]string, error) {
	// De-duplicate and sort so output is deterministic regardless of flag order.
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
		var (
			name string
			data []byte
			err  error
		)
		switch f {
		case "json":
			name = "report.json"
			data, err = jsonrender.Marshal(rep)
		case "html":
			name = "report.html"
			data, err = renderBytes(htmlrender.Renderer{}, rep)
		case "md", "markdown":
			name = "report.md"
			data, err = renderBytes(mdrender.Renderer{}, rep)
		case "pdf":
			name = "report.pdf"
			var engine report.PDFRenderer
			engine, err = pdfRenderer(pdfEngine)
			if err == nil {
				data, err = renderBytes(engine, rep)
			}
		default:
			return written, cli.Codedf(cli.ExitUsage, "unknown format %q (want json, html, md, pdf)", f)
		}
		if err != nil {
			return written, cli.Coded(cli.ExitInternal, err)
		}
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

func renderBytes(r report.Renderer, rep *report.Report) ([]byte, error) {
	var b bytes.Buffer
	if err := r.Render(rep, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
