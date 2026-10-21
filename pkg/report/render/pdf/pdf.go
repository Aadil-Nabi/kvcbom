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
	d.findings(r)
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

// row writes a table row with the given column widths and right-most column wrapping.
func (d *doc) row(widths []float64, cells []string, bold bool) {
	style := ""
	if bold {
		style = "B"
	}
	d.pdf.SetFont("Helvetica", style, 9)
	x, y := d.pdf.GetXY()
	// Measure the wrapped height of the last cell to size the row.
	last := len(cells) - 1
	lines := d.pdf.SplitLines([]byte(d.tr(cells[last])), widths[last])
	h := lh * float64(max(1, len(lines)))
	for i, c := range cells {
		cx, _ := d.pdf.GetXY()
		if i == last {
			d.pdf.MultiCell(widths[i], lh, d.tr(c), "1", "L", false)
			d.pdf.SetXY(cx+widths[i], y)
		} else {
			d.pdf.CellFormat(widths[i], h, d.tr(c), "1", 0, "L", false, 0, "")
		}
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

func (d *doc) findings(r *report.Report) {
	d.h2("Findings")
	if len(r.FindingGroups) == 0 {
		d.para("No findings.")
		return
	}
	d.para(fmt.Sprintf("Grouped by type; %d finding(s) in total.", len(r.Findings)))
	widths := []float64{22, 16, 142}
	d.row(widths, []string{"Severity", "Assets", "Finding"}, true)
	for _, g := range r.FindingGroups {
		txt := g.Title
		if len(g.Assets) > 0 {
			txt += ": " + capList(g.Assets, 6)
		}
		d.row(widths, []string{g.Severity, fmt.Sprintf("%d", g.Count), txt}, false)
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
		d.para(fmt.Sprintf("Applies to %d finding(s): %s.", item.FindingCount, strings.Join(item.FindingTypes, ", ")))
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
	widths := []float64{20, 52, 33, 15, 60}
	d.row(widths, []string{"Severity", "Algorithm", "Status", "Count", "Found at"}, true)
	for _, a := range r.AffectedAssets {
		d.row(widths, []string{a.Severity, a.Name, a.Status, fmt.Sprintf("%d", a.Count), capList(a.Locations, 3)}, false)
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
