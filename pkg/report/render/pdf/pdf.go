// Package pdf renders a Report as PDF. Two engines sit behind report.PDFRenderer: the
// default pure-Go engine (go-pdf/fpdf) keeps the single-binary, air-gap guarantee, while
// the optional Chromium engine prints the self-contained HTML for higher fidelity when a
// browser is present. The pure-Go output is plain, professional, and black-and-white, as
// SPEC §9 asks.
package pdf

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"

	"github.com/Aadil-Nabi/kvcbom/pkg/report"
)

// PureGo renders the report with go-pdf/fpdf — no external process, fully offline.
type PureGo struct{}

// Name identifies the engine.
func (PureGo) Name() string { return "purego" }

// Available always reports true: the pure-Go engine has no external dependency.
func (PureGo) Available() (bool, string) { return true, "" }

const (
	pageW   = 210.0
	margin  = 15.0
	usableW = pageW - 2*margin
	lh      = 5.0 // line height mm
)

// Render implements report.Renderer / report.PDFRenderer.
func (PureGo) Render(r *report.Report, w io.Writer) error {
	pdf := fpdf.New("P", "mm", "A4", "")
	// Sort internal resource catalogs (fonts, etc.) so the output is byte-reproducible;
	// without this fpdf emits the font dictionary in Go-map order.
	pdf.SetCatalogSort(true)
	pdf.SetMargins(margin, margin, margin)
	pdf.SetAutoPageBreak(true, margin)
	pdf.SetTitle(clean(r.Title), true)
	pdf.SetCreator("kvcbom", true)
	// Deterministic metadata: derive the document date from the injected timestamp.
	if t, err := time.Parse(time.RFC3339, r.GeneratedAt); err == nil {
		pdf.SetCreationDate(t.UTC())
		pdf.SetModificationDate(t.UTC())
	}
	tr := pdf.UnicodeTranslatorFromDescriptor("")
	d := &doc{pdf: pdf, tr: func(s string) string { return tr(clean(s)) }}

	pdf.AddPage()
	d.cover(r)
	d.warnings(r)
	d.summary(r)
	d.inventory(r)
	d.findings(r)
	d.systems(r)
	d.frameworks(r)
	d.remediation(r)
	d.affected(r)
	d.appendix(r)

	if err := pdf.Error(); err != nil {
		return fmt.Errorf("render PDF: %w", err)
	}
	return pdf.Output(w)
}

type doc struct {
	pdf *fpdf.Fpdf
	tr  func(string) string
}

func (d *doc) h1(s string) {
	d.pdf.SetFont("Helvetica", "B", 18)
	d.pdf.MultiCell(usableW, 8, d.tr(s), "", "L", false)
	d.pdf.Ln(2)
}

func (d *doc) h2(s string) {
	d.pdf.Ln(3)
	d.pdf.SetFont("Helvetica", "B", 13)
	d.pdf.MultiCell(usableW, 6, d.tr(s), "B", "L", false)
	d.pdf.Ln(1)
}

func (d *doc) para(s string) {
	d.pdf.SetFont("Helvetica", "", 10)
	d.pdf.MultiCell(usableW, lh, d.tr(s), "", "L", false)
	d.pdf.Ln(1)
}

func (d *doc) kv(k, v string) {
	d.pdf.SetFont("Helvetica", "B", 10)
	d.pdf.CellFormat(45, lh, d.tr(k), "", 0, "L", false, 0, "")
	d.pdf.SetFont("Helvetica", "", 10)
	d.pdf.MultiCell(usableW-45, lh, d.tr(v), "", "L", false)
}

// ensure breaks to a new page if a block of height h would cross the bottom
// margin. Rows manage their own breaks this way so the per-cell writes never
// trigger fpdf's automatic page break mid-row, which would desync the manual
// X/Y bookkeeping and leave a full-page gap after every row.
func (d *doc) ensure(h float64) {
	_, pageH := d.pdf.GetPageSize()
	_, y := d.pdf.GetXY()
	if y+h > pageH-margin {
		d.pdf.AddPage()
	}
}

// row writes a table row with the given column widths. Every column wraps to its
// width, and the row is sized to the tallest cell, so long text in any column
// (not just the last) stays inside its own box instead of overflowing neighbours.
func (d *doc) row(widths []float64, cells []string, bold bool) {
	style := ""
	if bold {
		style = "B"
	}
	d.pdf.SetFont("Helvetica", style, 9)
	// Wrap every cell to its column width and size the row to the tallest one.
	texts := make([]string, len(cells))
	maxLines := 1
	for i, c := range cells {
		texts[i] = d.tr(c)
		if n := len(d.pdf.SplitLines([]byte(texts[i]), widths[i])); n > maxLines {
			maxLines = n
		}
	}
	h := lh * float64(maxLines)
	// Keep the whole row on one page before capturing the row origin, so no
	// cell below triggers an auto page break partway through the row.
	d.ensure(h)
	x, y := d.pdf.GetXY()
	cx := x
	for i, t := range texts {
		// Full-height border box, then top-aligned wrapped text inside it.
		d.pdf.Rect(cx, y, widths[i], h, "D")
		d.pdf.SetXY(cx, y)
		d.pdf.MultiCell(widths[i], lh, t, "", "L", false)
		cx += widths[i]
	}
	d.pdf.SetXY(x, y+h)
}

func (d *doc) cover(r *report.Report) {
	d.h1(r.Title)
	if r.Assessment.Organisation != "" {
		d.kv("Organisation", r.Assessment.Organisation)
	}
	if r.Assessment.Scope != "" {
		d.kv("Scope", r.Assessment.Scope)
	}
	if r.Assessment.Assessor != "" {
		d.kv("Assessor", r.Assessment.Assessor)
	}
	d.kv("Generated", r.GeneratedAt)
	d.kv("Tool", r.Tool.Name+" "+r.Tool.Version)
	d.kv("Rule pack", fmt.Sprintf("%s %s (%s)", r.Pack.ID, r.Pack.Version, r.Pack.Status))
	for _, in := range r.Inputs {
		d.kv("Input", in.File+"  sha256="+in.SHA256)
	}
}

func (d *doc) warnings(r *report.Report) {
	if len(r.Warnings.Messages) == 0 {
		return
	}
	d.h2("Warnings")
	for _, m := range r.Warnings.Messages {
		d.para("- " + m)
	}
}

func (d *doc) summary(r *report.Report) {
	d.h2("Executive summary")
	d.para(fmt.Sprintf("This assessment covers %d cryptographic asset(s) and raised %d finding(s). Harvest-now-decrypt-later (HNDL) exposure: %d asset(s).",
		r.Summary.TotalAssets, r.Summary.TotalFindings, r.Summary.HNDLAssetCount))

	if len(r.Summary.TopRisks) > 0 {
		d.para("Top risks:")
		widths := []float64{70, 45, 20, 45}
		d.row(widths, []string{"Asset", "Quantum status", "Score", "HNDL"}, true)
		for _, t := range r.Summary.TopRisks {
			d.row(widths, []string{t.Name, t.QuantumStatus, fmt.Sprintf("%.2f", t.Final), yesno(t.HNDL)}, false)
		}
	}

	if len(r.Summary.MoscaByScenario) > 0 {
		d.pdf.Ln(2)
		d.para("Mosca exposure by scenario:")
		widths := []float64{60, 40, 40, 40}
		d.row(widths, []string{"Scenario", "Years to CRQC", "Exposed", "HNDL"}, true)
		for _, m := range r.Summary.MoscaByScenario {
			d.row(widths, []string{m.Scenario, trimFloat(m.YearsUntil), fmt.Sprintf("%d", m.ExposedAssets), fmt.Sprintf("%d", m.HNDLAssets)}, false)
		}
	}
}

// counts renders a labelled two-column tally table, matching the HTML inventory blocks.
func (d *doc) counts(title string, cs []report.Count) {
	if len(cs) == 0 {
		return
	}
	d.pdf.Ln(1)
	d.pdf.SetFont("Helvetica", "B", 10)
	d.pdf.MultiCell(usableW, lh, d.tr(title), "", "L", false)
	widths := []float64{140, 40}
	d.row(widths, []string{"", "Count"}, true)
	for _, c := range cs {
		d.row(widths, []string{c.Key, fmt.Sprintf("%d", c.Count)}, false)
	}
}

func (d *doc) inventory(r *report.Report) {
	inv := r.Inventory
	if len(inv.ByType)+len(inv.ByQuantumStatus)+len(inv.ByConfidence)+len(inv.BySystem) == 0 {
		return
	}
	d.h2("Inventory")
	d.counts("By asset type", inv.ByType)
	d.counts("By quantum status", inv.ByQuantumStatus)
	d.counts("By evidence confidence", inv.ByConfidence)
	d.counts("By system", inv.BySystem)
}

func (d *doc) findings(r *report.Report) {
	d.h2("Findings")
	if len(r.FindingGroups) == 0 {
		d.para("No findings.")
		return
	}
	d.para(fmt.Sprintf("Grouped by type; %d finding(s) in total.", len(r.Findings)))
	widths := []float64{20, 86, 14, 60}
	d.row(widths, []string{"Severity", "Finding", "Assets", "Affected"}, true)
	for _, g := range r.FindingGroups {
		finding := g.Title
		if g.Explanation != "" {
			finding += "\n" + g.Explanation
		}
		if g.RequiresVerification > 0 {
			finding += fmt.Sprintf("\n%d require verification", g.RequiresVerification)
		}
		d.row(widths, []string{g.Severity, finding, fmt.Sprintf("%d", g.Count), capList(g.Assets, 12)}, false)
	}
}

func (d *doc) systems(r *report.Report) {
	if len(r.Systems) == 0 {
		return
	}
	d.h2("Per-system view")
	for _, s := range r.Systems {
		name := s.System.Name
		if s.System.CrownJewel {
			name += " (crown jewel)"
		}
		d.pdf.Ln(1)
		d.pdf.SetFont("Helvetica", "B", 11)
		d.pdf.MultiCell(usableW, lh, d.tr(name), "", "L", false)
		d.para(fmt.Sprintf("Criticality: %s. Assets: %d. Worst score: %.2f.",
			s.System.Criticality, len(s.AssetIDs), s.WorstFinal))
		if len(s.FindingCounts) > 0 {
			var b strings.Builder
			b.WriteString("Findings: ")
			for _, c := range s.FindingCounts {
				fmt.Fprintf(&b, "%s %d; ", c.Key, c.Count)
			}
			d.para(b.String())
		}
	}
}

func capList(names []string, n int) string {
	if len(names) <= n {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:n], ", ") + fmt.Sprintf(" (+%d more)", len(names)-n)
}

func (d *doc) remediation(r *report.Report) {
	if len(r.Remediation) == 0 {
		return
	}
	d.h2("Remediation roadmap")
	for _, item := range r.Remediation {
		d.pdf.SetFont("Helvetica", "B", 10)
		d.pdf.MultiCell(usableW, lh, d.tr(strings.ToUpper(item.TopSeverity)+" - "+item.Summary), "", "L", false)
		if item.Detail != "" {
			d.para(item.Detail)
		}
		applies := fmt.Sprintf("Applies to %d finding(s): %s.", item.FindingCount, strings.Join(item.FindingTypes, ", "))
		if len(item.References) > 0 {
			applies += " References: " + strings.Join(item.References, ", ") + "."
		}
		d.para(applies)
	}
}

func (d *doc) frameworks(r *report.Report) {
	if len(r.Frameworks) == 0 {
		return
	}
	d.h2("Framework mapping")
	for _, fw := range r.Frameworks {
		d.pdf.SetFont("Helvetica", "B", 11)
		d.pdf.MultiCell(usableW, lh, d.tr(fw.Name), "", "L", false)
		widths := []float64{70, 80, 18, 22}
		d.row(widths, []string{"Finding type", "Control", "Count", "Verified"}, true)
		for _, m := range fw.Mappings {
			verified := "yes"
			if m.Unverified {
				verified = "NO (TODO)"
			}
			d.row(widths, []string{m.FindingType, m.ControlID, fmt.Sprintf("%d", m.FindingCount), verified}, false)
		}
		d.pdf.Ln(2)
	}
}

func (d *doc) affected(r *report.Report) {
	if len(r.AffectedAssets) == 0 {
		return
	}
	d.h2("Affected assets - remediation detail")
	d.para(fmt.Sprintf("The %d algorithm(s) that need action, with where each was found.", len(r.AffectedAssets)))
	widths := []float64{15, 42, 30, 20, 23, 50}
	d.row(widths, []string{"Severity", "Algorithm", "Status", "Role", "Occurrences", "Found at"}, true)
	for _, a := range r.AffectedAssets {
		d.row(widths, []string{a.Severity, a.Name, a.Status, a.Primitive, fmt.Sprintf("%d", a.Count), capList(a.Locations, 6)}, false)
	}
}

func (d *doc) appendix(r *report.Report) {
	d.h2("Appendix")
	d.pdf.SetFont("Helvetica", "B", 10)
	d.pdf.MultiCell(usableW, lh, d.tr("Methodology"), "", "L", false)
	d.para(r.Appendix.Methodology)
	d.pdf.SetFont("Helvetica", "B", 10)
	d.pdf.MultiCell(usableW, lh, d.tr("Scoring"), "", "L", false)
	d.para(r.Appendix.ScoringFormula)
	if len(r.Appendix.MergeDecisions) > 0 {
		d.pdf.SetFont("Helvetica", "B", 10)
		d.pdf.MultiCell(usableW, lh, d.tr("Merge decisions"), "", "L", false)
		d.para(fmt.Sprintf("%d asset(s) were formed by merging duplicate records across inputs.", len(r.Appendix.MergeDecisions)))
		for _, m := range r.Appendix.MergeDecisions {
			name := ""
			if m.AssetName != "" {
				name = m.AssetName + " "
			}
			d.para(fmt.Sprintf("- %s(%s) - merged %d source record(s)", name, m.AssetID, len(m.Sources)))
		}
	}
	if len(r.Appendix.Sources) > 0 {
		d.pdf.SetFont("Helvetica", "B", 10)
		d.pdf.MultiCell(usableW, lh, d.tr("Sources"), "", "L", false)
		for _, s := range r.Appendix.Sources {
			d.para(fmt.Sprintf("- %s [%s]: %s  %s", s.ID, s.Status, s.Title, s.URL))
		}
	}
}

func yesno(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func trimFloat(f float64) string {
	return strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%.1f", f), "0"), ".")
}

// clean replaces the few non-Windows-1252 characters the report text can contain, so the
// core PDF fonts render them instead of dropping them.
func clean(s string) string {
	return strings.NewReplacer(
		"→", "->", // →
		"≥", ">=", // ≥
		"≤", "<=", // ≤
		"≡", "==", // ≡
	).Replace(s)
}
