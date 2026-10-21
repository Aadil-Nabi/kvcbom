package main

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Aadil-Nabi/kvcbom/internal/cli"
	"github.com/Aadil-Nabi/kvcbom/pkg/rulepack"
)

func newRulepacksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rulepacks",
		Short: "List, inspect, and validate rule packs",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newRulepacksListCmd(), newRulepacksShowCmd(), newRulepacksValidateCmd())
	return cmd
}

// ---- list ----

func newRulepacksListCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the rule packs embedded in the binary",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			metas, err := rulepack.List()
			if err != nil {
				return cli.Coded(cli.ExitInternal, err)
			}
			if asJSON {
				return encodeJSON(cmd.OutOrStdout(), metas)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tVERSION\tSTATUS\tNAME")
			for _, m := range metas {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.ID, m.Version, m.Status, m.Name)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

// ---- show ----

type showView struct {
	Meta            rulepack.Meta `json:"meta"`
	Classifications int           `json:"classification_count"`
	Rules           []ruleView    `json:"rules"`
	Remediation     []string      `json:"remediation_ids"`
	Framework       string        `json:"framework,omitempty"`
	HasUnverified   bool          `json:"has_unverified_content"`
}

type ruleView struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	FindingType string `json:"finding_type"`
	Title       string `json:"title"`
}

func newRulepacksShowCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show <id|path>",
		Short: "Show a rule pack's metadata, sources, and rules",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lp, err := rulepack.Load(args[0])
			if err != nil {
				return cli.Coded(cli.ExitValidation, err)
			}
			p := lp.Pack
			view := showView{
				Meta:            p.Meta(),
				Classifications: len(p.ClassificationEntries()),
				Remediation:     p.RemediationIDs(),
				Framework:       p.Framework().ID,
				HasUnverified:   p.HasUnverifiedContent(),
			}
			for _, r := range p.Rules() {
				view.Rules = append(view.Rules, ruleView{
					ID: r.ID, Severity: string(r.Severity), FindingType: r.FindingType, Title: r.Title,
				})
			}
			if asJSON {
				return encodeJSON(cmd.OutOrStdout(), view)
			}
			printShowHuman(cmd.OutOrStdout(), lp, view)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func printShowHuman(w io.Writer, lp *rulepack.LoadedPack, v showView) {
	p := lp.Pack
	fmt.Fprintf(w, "%s %s (%s)\n", v.Meta.ID, v.Meta.Version, v.Meta.Status)
	fmt.Fprintf(w, "%s\n", v.Meta.Name)
	fmt.Fprintf(w, "origin: %s\nsha256: %s\n\n", lp.Origin, lp.SHA256)
	if v.HasUnverified {
		fmt.Fprintln(w, "WARNING: this pack carries unverified content (draft/vendor status or TODO(source) markers).")
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "classifications: %d\n", v.Classifications)

	fmt.Fprintf(w, "\nsources (%d):\n", len(v.Meta.Sources))
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, s := range v.Meta.Sources {
		fmt.Fprintf(tw, "  %s\t[%s]\t%s\n", s.ID, s.Status, s.URL)
	}
	_ = tw.Flush()

	fmt.Fprintf(w, "\nrules (%d):\n", len(v.Rules))
	tw = tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	for _, r := range v.Rules {
		fmt.Fprintf(tw, "  %s\t[%s]\t%s\n", r.ID, r.Severity, r.FindingType)
	}
	_ = tw.Flush()

	if fw := p.Framework(); fw.ID != "" {
		fmt.Fprintf(w, "\nframework: %s (%s), %d mapping(s)\n", fw.ID, fw.Name, len(fw.Mappings))
	}
}

// ---- validate ----

func newRulepacksValidateCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "validate <id|path>",
		Short: "Validate a rule pack; exit code 2 on any error",
		Long: "validate loads a pack (embedded id or file path), checks it against the\n" +
			"rule-pack schema, and reports semantic issues: a missing source reference is an\n" +
			"error; a remaining TODO(source) marker is a warning. Errors exit with code 2.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			lp, err := rulepack.Load(args[0])
			if err != nil {
				// A pack that fails to load (bad YAML/schema) is itself a validation failure.
				return cli.Coded(cli.ExitValidation, err)
			}
			issues := lp.Pack.Validate()

			errCount := 0
			for _, is := range issues {
				if is.Level == rulepack.LevelError {
					errCount++
				}
			}

			if asJSON {
				if err := encodeJSON(cmd.OutOrStdout(), issues); err != nil {
					return err
				}
			} else {
				w := cmd.ErrOrStderr()
				if len(issues) == 0 {
					fmt.Fprintf(w, "%s %s: OK (no issues)\n", lp.Pack.Meta().ID, lp.Pack.Meta().Version)
				}
				for _, is := range issues {
					fmt.Fprintln(w, is.String())
				}
				fmt.Fprintf(w, "\n%d error(s), %d issue(s) total\n", errCount, len(issues))
			}

			if errCount > 0 {
				return cli.Codedf(cli.ExitValidation, "rule pack has %d error(s)", errCount)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

// encodeJSON writes v as deterministic, human-readable JSON to w.
func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return cli.Coded(cli.ExitInternal, err)
	}
	return nil
}
