package main

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Aadil-Nabi/kvcbom/internal/cli"
	"github.com/Aadil-Nabi/kvcbom/internal/version"
	"github.com/Aadil-Nabi/kvcbom/pkg/ingest/cbom"
	ctxingest "github.com/Aadil-Nabi/kvcbom/pkg/ingest/context"
)

// validateFileReport is the per-file result of `validate`.
type validateFileReport struct {
	File         string                   `json:"file"`
	SHA256       string                   `json:"sha256,omitempty"`
	SchemaValid  bool                     `json:"schema_valid"`
	SchemaError  string                   `json:"schema_error,omitempty"`
	AssetCount   int                      `json:"asset_count"`
	Completeness []cbom.CompletenessIssue `json:"completeness"`
}

// validateContextReport is the context-file result, present when --context is given.
type validateContextReport struct {
	File         string            `json:"file"`
	SHA256       string            `json:"sha256,omitempty"`
	Valid        bool              `json:"valid"`
	Error        string            `json:"error,omitempty"`
	Completeness []ctxingest.Issue `json:"completeness,omitempty"`
}

// validateReport is the top-level `validate --json` payload.
type validateReport struct {
	Tool    string                 `json:"tool"`
	Version string                 `json:"version"`
	OK      bool                   `json:"ok"`
	Files   []validateFileReport   `json:"files"`
	Context *validateContextReport `json:"context,omitempty"`
}

func newValidateCmd() *cobra.Command {
	var (
		cbomFiles   []string
		contextFile string
		strict      bool
		asJSON      bool
		maxBytes    int64
		cbomMapping string
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate CBOMs against CycloneDX 1.6 and report completeness gaps",
		Long: "validate schema-checks each CBOM against CycloneDX 1.6 and lists fields that,\n" +
			"if missing, weaken risk scoring. Exit code 2 indicates a validation failure;\n" +
			"with --strict, completeness warnings also fail.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if len(cbomFiles) == 0 {
				return cli.Codedf(cli.ExitUsage, "at least one --cbom is required")
			}

			var cbomMap *cbom.Mapping
			if cbomMapping != "" {
				var err error
				cbomMap, err = cbom.LoadMapping(cbomMapping)
				if err != nil {
					return cli.Coded(cli.ExitValidation, err)
				}
			}

			rep := validateReport{Tool: "kvcbom", Version: version.Version, OK: true}

			for _, path := range cbomFiles {
				fr := validateFileReport{File: path, SchemaValid: true}

				res, err := cbom.IngestFile(path, cbom.Options{MaxInputBytes: maxBytes, ValidateSchema: true, Mapping: cbomMap})
				if err != nil {
					fr.SchemaValid = false
					fr.SchemaError = err.Error()
					rep.OK = false
					rep.Files = append(rep.Files, fr)
					continue
				}

				fr.SHA256 = res.Batch.SourceSHA256
				fr.AssetCount = len(res.Batch.Assets)
				fr.Completeness = res.Completeness
				if res.SchemaError != nil {
					fr.SchemaValid = false
					fr.SchemaError = res.SchemaError.Error()
					rep.OK = false
				}
				if strict {
					for _, is := range res.Completeness {
						if is.Severity == cbom.SeverityWarn {
							rep.OK = false
							break
						}
					}
				}
				rep.Files = append(rep.Files, fr)
			}

			if contextFile != "" {
				cr := &validateContextReport{File: contextFile, Valid: true}
				res, err := ctxingest.LoadFile(contextFile)
				if err != nil {
					cr.Valid = false
					cr.Error = err.Error()
					rep.OK = false
				} else {
					cr.SHA256 = res.SHA256
					cr.Completeness = res.Completeness
					if strict {
						for _, is := range res.Completeness {
							if is.Level == ctxingest.LevelWarn {
								rep.OK = false
								break
							}
						}
					}
				}
				rep.Context = cr
			}

			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				enc.SetEscapeHTML(false)
				if err := enc.Encode(rep); err != nil {
					return cli.Coded(cli.ExitInternal, err)
				}
			} else {
				printValidateHuman(cmd.ErrOrStderr(), rep)
			}

			if !rep.OK {
				return cli.Codedf(cli.ExitValidation, "one or more CBOMs failed validation")
			}
			return nil
		},
	}

	cmd.Flags().StringArrayVar(&cbomFiles, "cbom", nil, "path to a CBOM file (repeatable)")
	cmd.Flags().StringVar(&contextFile, "context", "", "path to an assessment context file to validate")
	cmd.Flags().BoolVar(&strict, "strict", false, "treat completeness warnings as validation failures")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit machine-readable JSON to stdout")
	cmd.Flags().Int64Var(&maxBytes, "max-bytes", 0, "maximum input file size in bytes (0 = default)")
	cmd.Flags().StringVar(&cbomMapping, "cbom-mapping", "", "path to a CBOM extension-mapping YAML (maps vendor property keys to the algorithm)")
	return cmd
}

func printValidateHuman(w io.Writer, rep validateReport) {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, f := range rep.Files {
		status := "VALID"
		if !f.SchemaValid {
			status = "INVALID"
		}
		fmt.Fprintf(tw, "%s\t[%s]\t%d assets\n", f.File, status, f.AssetCount)
		if f.SchemaError != "" {
			fmt.Fprintf(tw, "  schema\t \t%s\n", f.SchemaError)
		}
		for _, is := range f.Completeness {
			name := is.AssetName
			if name == "" {
				name = is.AssetID
			}
			fmt.Fprintf(tw, "  [%s]\t%s\t%s: %s\n", is.Severity, name, is.Field, is.Message)
		}
	}
	_ = tw.Flush()

	if rep.Context != nil {
		c := rep.Context
		status := "VALID"
		if !c.Valid {
			status = "INVALID"
		}
		fmt.Fprintf(w, "\ncontext %s [%s]\n", c.File, status)
		if c.Error != "" {
			fmt.Fprintf(w, "  %s\n", c.Error)
		}
		ctw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		for _, is := range c.Completeness {
			fmt.Fprintf(ctw, "  [%s]\t%s\t%s\n", is.Level, is.Location, is.Message)
		}
		_ = ctw.Flush()
	}

	if rep.OK {
		fmt.Fprintln(w, "\nAll inputs valid.")
	} else {
		fmt.Fprintln(w, "\nValidation failed.")
	}
	fmt.Fprintln(w, "Note: business-context links (systems, data classes) come from a context file;")
	fmt.Fprintln(w, "supply one to `report` for full risk scoring.")
}
