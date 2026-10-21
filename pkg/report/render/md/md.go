// Package md renders a Report as Markdown for pasting into wikis and tickets (SPEC §9).
// It reads only the canonical Report; all ordering is already deterministic there.
package md

import (
	"fmt"
	"io"
	"strings"

	"github.com/Aadil-Nabi/kvcbom/pkg/report"
)

// Renderer writes a Report as Markdown.
type Renderer struct{}

// Render implements report.Renderer.
func (Renderer) Render(r *report.Report, w io.Writer) error {
	b := &strings.Builder{}

	fmt.Fprintf(b, "# %s\n\n", r.Title)
	writeMeta(b, r)
	writeWarnings(b, r)
	writeSummary(b, r)
	writeInventory(b, r)
	writeFindings(b, r)
	writeSystems(b, r)
	writeFramework(b, r)
	writeRemediation(b, r)
	writeAppendix(b, r)

	_, err := io.WriteString(w, b.String())
	return err
}

func writeMeta(b *strings.Builder, r *report.Report) {
	if r.Assessment.Organisation != "" {
		fmt.Fprintf(b, "**Organisation:** %s  \n", r.Assessment.Organisation)
	}
	if r.Assessment.Scope != "" {
		fmt.Fprintf(b, "**Scope:** %s  \n", r.Assessment.Scope)
	}
	if r.Assessment.Assessor != "" {
		fmt.Fprintf(b, "**Assessor:** %s  \n", r.Assessment.Assessor)
	}
	fmt.Fprintf(b, "**Generated:** %s  \n", r.GeneratedAt)
	fmt.Fprintf(b, "**Tool:** %s %s  \n", r.Tool.Name, r.Tool.Version)
	fmt.Fprintf(b, "**Rule pack:** %s %s (%s)  \n", r.Pack.ID, r.Pack.Version, r.Pack.Status)
	fmt.Fprintf(b, "\n")

	if len(r.Inputs) > 0 {
		fmt.Fprintf(b, "**Inputs:**\n\n")
		for _, in := range r.Inputs {
			fmt.Fprintf(b, "- `%s` — `%s`\n", in.File, in.SHA256)
		}
		fmt.Fprintf(b, "\n")
	}
}

func writeWarnings(b *strings.Builder, r *report.Report) {
	if len(r.Warnings.Messages) == 0 {
		return
	}
	fmt.Fprintf(b, "## Warnings\n\n")
	for _, m := range r.Warnings.Messages {
		fmt.Fprintf(b, "- %s\n", m)
	}
	fmt.Fprintf(b, "\n")
}

func writeSummary(b *strings.Builder, r *report.Report) {
	s := r.Summary
	fmt.Fprintf(b, "## Executive summary\n\n")
	fmt.Fprintf(b, "This assessment covers **%d cryptographic asset(s)** and raised **%d finding(s)**.\n\n", s.TotalAssets, s.TotalFindings)

	if len(s.FindingsBySev) > 0 {
		fmt.Fprintf(b, "Findings by severity: ")
		parts := make([]string, 0, len(s.FindingsBySev))
		for _, c := range s.FindingsBySev {
			parts = append(parts, fmt.Sprintf("%s %d", c.Key, c.Count))
		}
		fmt.Fprintf(b, "%s.\n\n", strings.Join(parts, ", "))
	}

	fmt.Fprintf(b, "Harvest-now-decrypt-later (HNDL) exposure: **%d asset(s)**.\n\n", s.HNDLAssetCount)

	if len(s.TopRisks) > 0 {
		fmt.Fprintf(b, "### Top risks\n\n")
		fmt.Fprintf(b, "| Asset | Quantum status | HNDL | Score |\n|---|---|---|---|\n")
		for _, t := range s.TopRisks {
			fmt.Fprintf(b, "| %s | %s | %s | %.2f |\n", mdEsc(t.Name), t.QuantumStatus, yesno(t.HNDL), t.Final)
		}
		fmt.Fprintf(b, "\n")
	}

	if len(s.MoscaByScenario) > 0 {
		fmt.Fprintf(b, "### Mosca exposure by scenario\n\n")
		fmt.Fprintf(b, "| Scenario | Years until CRQC | Exposed assets | HNDL assets |\n|---|---|---|---|\n")
		for _, m := range s.MoscaByScenario {
			fmt.Fprintf(b, "| %s | %g | %d | %d |\n", m.Scenario, m.YearsUntil, m.ExposedAssets, m.HNDLAssets)
		}
		fmt.Fprintf(b, "\n")
	}
}

func writeInventory(b *strings.Builder, r *report.Report) {
	fmt.Fprintf(b, "## Inventory\n\n")
	writeCountTable(b, "By asset type", r.Inventory.ByType)
	writeCountTable(b, "By quantum status", r.Inventory.ByQuantumStatus)
	writeCountTable(b, "By evidence confidence", r.Inventory.ByConfidence)
	writeCountTable(b, "By system", r.Inventory.BySystem)
}

func writeCountTable(b *strings.Builder, title string, counts []report.Count) {
	if len(counts) == 0 {
		return
	}
	fmt.Fprintf(b, "**%s**\n\n| | Count |\n|---|---|\n", title)
	for _, c := range counts {
		fmt.Fprintf(b, "| %s | %d |\n", mdEsc(c.Key), c.Count)
	}
	fmt.Fprintf(b, "\n")
}

func writeFindings(b *strings.Builder, r *report.Report) {
	fmt.Fprintf(b, "## Findings\n\n")
	if len(r.Findings) == 0 {
		fmt.Fprintf(b, "No findings.\n\n")
		return
	}
	fmt.Fprintf(b, "| Severity | Finding | Asset | Verify |\n|---|---|---|---|\n")
	for _, f := range r.Findings {
		fmt.Fprintf(b, "| %s | %s | `%s` | %s |\n",
			f.Severity, mdEsc(f.Title), f.AssetID, yesno(f.RequiresVerification))
	}
	fmt.Fprintf(b, "\n")
}

func writeSystems(b *strings.Builder, r *report.Report) {
	if len(r.Systems) == 0 {
		return
	}
	fmt.Fprintf(b, "## Per-system view\n\n")
	for _, sv := range r.Systems {
		fmt.Fprintf(b, "### %s", mdEsc(sv.System.Name))
		if sv.System.CrownJewel {
			fmt.Fprintf(b, " (crown jewel)")
		}
		fmt.Fprintf(b, "\n\n")
		fmt.Fprintf(b, "Criticality: %s. Assets: %d. Worst score: %.2f.\n\n",
			sv.System.Criticality, len(sv.AssetIDs), sv.WorstFinal)
		if len(sv.FindingCounts) > 0 {
			parts := make([]string, 0, len(sv.FindingCounts))
			for _, c := range sv.FindingCounts {
				parts = append(parts, fmt.Sprintf("%s %d", c.Key, c.Count))
			}
			fmt.Fprintf(b, "Findings: %s.\n\n", strings.Join(parts, ", "))
		}
	}
}

func writeFramework(b *strings.Builder, r *report.Report) {
	if r.Framework == nil {
		return
	}
	fmt.Fprintf(b, "## Framework mapping — %s\n\n", mdEsc(r.Framework.Name))
	fmt.Fprintf(b, "| Finding type | Control | Findings | Verified |\n|---|---|---|---|\n")
	for _, m := range r.Framework.Mappings {
		verified := "yes"
		if m.Unverified {
			verified = "NO (TODO)"
		}
		fmt.Fprintf(b, "| %s | %s | %d | %s |\n", m.FindingType, mdEsc(m.ControlID), m.FindingCount, verified)
	}
	fmt.Fprintf(b, "\n")
}

func writeRemediation(b *strings.Builder, r *report.Report) {
	if len(r.Remediation) == 0 {
		return
	}
	fmt.Fprintf(b, "## Remediation roadmap\n\n")
	for _, item := range r.Remediation {
		fmt.Fprintf(b, "### %s — %s\n\n", strings.ToUpper(item.TopSeverity), mdEsc(item.Summary))
		if item.Detail != "" {
			fmt.Fprintf(b, "%s\n\n", mdEsc(item.Detail))
		}
		fmt.Fprintf(b, "Applies to %d finding(s): %s.\n\n", item.FindingCount, strings.Join(item.FindingTypes, ", "))
		if len(item.References) > 0 {
			fmt.Fprintf(b, "References: %s.\n\n", strings.Join(item.References, ", "))
		}
	}
}

func writeAppendix(b *strings.Builder, r *report.Report) {
	fmt.Fprintf(b, "## Appendix\n\n")
	fmt.Fprintf(b, "### Methodology\n\n%s\n\n", r.Appendix.Methodology)
	fmt.Fprintf(b, "### Scoring\n\n%s\n\n", r.Appendix.ScoringFormula)

	if len(r.Appendix.MergeDecisions) > 0 {
		fmt.Fprintf(b, "### Merge decisions\n\n")
		for _, d := range r.Appendix.MergeDecisions {
			fmt.Fprintf(b, "- `%s` (%s) merged from: %s\n", d.AssetID, mdEsc(d.AssetName), strings.Join(d.Sources, ", "))
		}
		fmt.Fprintf(b, "\n")
	}

	if len(r.Appendix.Sources) > 0 {
		fmt.Fprintf(b, "### Sources\n\n")
		for _, s := range r.Appendix.Sources {
			fmt.Fprintf(b, "- **%s** [%s]: %s — %s\n", s.ID, s.Status, mdEsc(s.Title), s.URL)
		}
		fmt.Fprintf(b, "\n")
	}
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// mdEsc escapes the Markdown table/inline characters that would break layout.
func mdEsc(s string) string {
	r := strings.NewReplacer("|", "\\|", "\n", " ", "\r", "")
	return r.Replace(s)
}
