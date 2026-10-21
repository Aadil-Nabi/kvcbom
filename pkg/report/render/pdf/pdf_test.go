package pdf

import (
	"bytes"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/pkg/report"
)

func buildReport() *report.Report {
	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Name: "kvcbom", Version: "1.0.0-test"},
		GeneratedAt:   "2026-01-01T00:00:00Z",
		Title:         "Sample Report → unicode arrow",
		Assessment:    model.AssessmentMeta{Organisation: "Example Corp", Scope: "All systems"},
		Pack:          report.PackInfo{ID: "baseline-pqc", Version: "1.0.0", Status: "final"},
		Warnings:      report.Warnings{Messages: []string{"1 finding requires verification"}},
		Summary: report.Summary{
			TotalAssets: 2, TotalFindings: 1, HNDLAssetCount: 1,
			TopRisks: []report.RiskRef{
				{AssetID: "abc123", Name: "RSA-2048", QuantumStatus: "shor_broken", Final: 0.9, HNDL: true},
			},
			MoscaByScenario: []report.ScenarioOutcome{{Scenario: "central", YearsUntil: 10, ExposedAssets: 1, HNDLAssets: 1}},
		},
		Findings: []model.Finding{
			{RuleID: "BLP-ASYM-SHOR", FindingType: "quantum-vulnerable-asymmetric", Severity: model.SeverityCritical,
				AssetID: "abc123", Title: "Public-key algorithm broken by Shor's algorithm", RequiresVerification: true},
		},
		Remediation: []report.RemediationItem{
			{ID: "migrate", Summary: "Migrate to PQC", Detail: "Use ML-KEM and ML-DSA.",
				FindingTypes: []string{"quantum-vulnerable-asymmetric"}, FindingCount: 1, TopSeverity: "critical"},
		},
		Appendix: report.Appendix{
			Methodology:    "Assets are classified and scored; Mosca X + Y > Z per scenario.",
			ScoringFormula: "final = weighted sum of components",
			Sources:        []report.SourceView{{ID: "fips-203", Title: "FIPS 203", URL: "https://doi.org/10.6028/NIST.FIPS.203", Status: "final"}},
		},
	}
	return r
}

func TestPureGo_RendersValidPDF(t *testing.T) {
	var buf bytes.Buffer
	if err := (PureGo{}).Render(buildReport(), &buf); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.Bytes()
	if len(out) < 500 {
		t.Fatalf("PDF suspiciously small: %d bytes", len(out))
	}
	if !bytes.HasPrefix(out, []byte("%PDF-")) {
		t.Errorf("output is not a PDF (prefix %q)", out[:min(8, len(out))])
	}
	if !bytes.Contains(out, []byte("%%EOF")) {
		t.Error("PDF missing the EOF trailer")
	}
}

func TestPureGo_Deterministic(t *testing.T) {
	var a, b bytes.Buffer
	if err := (PureGo{}).Render(buildReport(), &a); err != nil {
		t.Fatal(err)
	}
	if err := (PureGo{}).Render(buildReport(), &b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("pure-Go PDF is not byte-identical across runs with the same timestamp")
	}
}

func TestPureGo_EmptyReport(t *testing.T) {
	r := &report.Report{SchemaVersion: report.SchemaVersion, Title: "Empty", GeneratedAt: "2026-01-01T00:00:00Z",
		Tool: report.ToolInfo{Name: "kvcbom", Version: "t"}, Pack: report.PackInfo{ID: "baseline-pqc", Version: "1.0.0"}}
	var buf bytes.Buffer
	if err := (PureGo{}).Render(r, &buf); err != nil {
		t.Fatalf("Render on empty report: %v", err)
	}
	if !bytes.HasPrefix(buf.Bytes(), []byte("%PDF-")) {
		t.Error("empty report did not produce a PDF")
	}
}

func TestChromium_Metadata(t *testing.T) {
	c := Chromium{}
	if c.Name() != "chromium" {
		t.Errorf("name = %q", c.Name())
	}
	// Available must not panic and must return a message when unavailable.
	ok, msg := c.Available()
	if !ok && msg == "" {
		t.Error("unavailable Chromium should return a reason")
	}

	// An explicitly unavailable binary name yields an error from Render, never a panic.
	bad := Chromium{Binary: "definitely-not-a-browser-xyz"}
	if _, ok := bad.resolve(); ok {
		// resolve trusts an explicit binary; Render will fail when it cannot exec.
		var buf bytes.Buffer
		if err := bad.Render(buildReport(), &buf); err == nil {
			t.Error("expected Render to fail with a bogus browser binary")
		}
	}
}

func TestPureGo_Available(t *testing.T) {
	if ok, _ := (PureGo{}).Available(); !ok {
		t.Error("pure-Go engine must always be available")
	}
}
