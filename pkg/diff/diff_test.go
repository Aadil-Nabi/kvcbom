package diff

import (
	"reflect"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/pkg/report"
)

func av(id, name string, status classify.QuantumStatus, final float64, hndl bool) report.AssetView {
	return report.AssetView{
		Asset:          model.Asset{ID: id, Name: name},
		Classified:     status != classify.StatusUnknown,
		Classification: classify.Result{Status: status},
		Score:          model.RiskScore{Final: final, HNDL: hndl},
	}
}

func finding(rule, assetID string, sev model.Severity) model.Finding {
	return model.Finding{RuleID: rule, FindingType: "t", Severity: sev, AssetID: assetID, Title: rule}
}

func mkReport(assets []report.AssetView, findings []model.Finding) *report.Report {
	return &report.Report{
		SchemaVersion: report.SchemaVersion,
		Tool:          report.ToolInfo{Version: "t"},
		Pack:          report.PackInfo{ID: "baseline-pqc", Version: "1.0.0"},
		Assets:        assets,
		Findings:      findings,
	}
}

func TestCompare_AddedRemovedChanged(t *testing.T) {
	base := mkReport(
		[]report.AssetView{
			av("a", "RSA", classify.StatusShorBroken, 0.8, true),
			av("b", "AES-256", classify.StatusQuantumResistant, 0.1, false),
		},
		[]model.Finding{finding("BLP-ASYM-SHOR", "a", model.SeverityCritical)},
	)
	cur := mkReport(
		[]report.AssetView{
			// a removed; b changed (score dropped, HNDL cleared); c added.
			av("b", "AES-256", classify.StatusQuantumResistant, 0.05, false),
			av("c", "ML-KEM", classify.StatusQuantumResistant, 0.1, false),
		},
		[]model.Finding{finding("BLP-PQC-IN-USE", "c", model.SeverityInfo)},
	)

	res := Compare(base, cur)

	if len(res.AssetsAdded) != 1 || res.AssetsAdded[0].AssetID != "c" {
		t.Errorf("assets added = %+v, want [c]", res.AssetsAdded)
	}
	if len(res.AssetsRemoved) != 1 || res.AssetsRemoved[0].AssetID != "a" {
		t.Errorf("assets removed = %+v, want [a]", res.AssetsRemoved)
	}
	if len(res.AssetsChanged) != 1 || res.AssetsChanged[0].AssetID != "b" {
		t.Fatalf("assets changed = %+v, want [b]", res.AssetsChanged)
	}
	ch := res.AssetsChanged[0]
	if !ch.ScoreChanged || ch.StatusChanged {
		t.Errorf("b: expected score change only, got %+v", ch)
	}
	if ch.Regressed {
		t.Error("b improved (score dropped); should not be a regression")
	}

	if len(res.FindingsAdded) != 1 || res.FindingsAdded[0].RuleID != "BLP-PQC-IN-USE" {
		t.Errorf("findings added = %+v", res.FindingsAdded)
	}
	if len(res.FindingsResolved) != 1 || res.FindingsResolved[0].RuleID != "BLP-ASYM-SHOR" {
		t.Errorf("findings resolved = %+v", res.FindingsResolved)
	}

	if res.Summary.AssetsAdded != 1 || res.Summary.AssetsRemoved != 1 || res.Summary.AssetsChanged != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
	if res.Summary.FindingsAdded != 1 || res.Summary.FindingsResolved != 1 {
		t.Errorf("summary findings = %+v", res.Summary)
	}
}

func TestCompare_Regression(t *testing.T) {
	base := mkReport([]report.AssetView{av("a", "AES", classify.StatusGroverWeakened, 0.4, false)}, nil)
	cur := mkReport([]report.AssetView{av("a", "AES", classify.StatusShorBroken, 0.9, true)}, nil)
	res := Compare(base, cur)
	if len(res.AssetsChanged) != 1 {
		t.Fatalf("expected one change, got %d", len(res.AssetsChanged))
	}
	ch := res.AssetsChanged[0]
	if !ch.Regressed || !ch.StatusChanged || !ch.ScoreChanged {
		t.Errorf("expected a full regression, got %+v", ch)
	}
	if !ch.ToHNDL || ch.FromHNDL {
		t.Errorf("expected HNDL newly set, got from=%v to=%v", ch.FromHNDL, ch.ToHNDL)
	}
}

func TestCompare_NewFindingsBySeverity(t *testing.T) {
	base := mkReport([]report.AssetView{av("a", "x", classify.StatusShorBroken, 0.5, false)}, nil)
	cur := mkReport([]report.AssetView{av("a", "x", classify.StatusShorBroken, 0.5, false)},
		[]model.Finding{
			finding("R1", "a", model.SeverityCritical),
			finding("R2", "a", model.SeverityInfo),
		})
	res := Compare(base, cur)
	want := []SeverityCount{{Severity: "critical", Count: 1}, {Severity: "info", Count: 1}}
	if !reflect.DeepEqual(res.Summary.NewFindingsBySev, want) {
		t.Errorf("new findings by severity = %+v, want %+v", res.Summary.NewFindingsBySev, want)
	}
}

func TestCompare_NoChanges(t *testing.T) {
	r := mkReport([]report.AssetView{av("a", "x", classify.StatusShorBroken, 0.5, false)},
		[]model.Finding{finding("R1", "a", model.SeverityCritical)})
	res := Compare(r, r)
	if res.Summary.AssetsAdded+res.Summary.AssetsRemoved+res.Summary.AssetsChanged != 0 {
		t.Errorf("expected no asset changes, got %+v", res.Summary)
	}
	if res.Summary.FindingsAdded+res.Summary.FindingsResolved != 0 {
		t.Errorf("expected no finding changes, got %+v", res.Summary)
	}
}

func TestCompare_Deterministic(t *testing.T) {
	base := mkReport([]report.AssetView{av("a", "RSA", classify.StatusShorBroken, 0.8, true)}, nil)
	cur := mkReport([]report.AssetView{
		av("c", "ML-KEM", classify.StatusQuantumResistant, 0.1, false),
		av("b", "AES", classify.StatusQuantumResistant, 0.1, false),
	}, nil)
	r1 := Compare(base, cur)
	r2 := Compare(base, cur)
	if !reflect.DeepEqual(r1, r2) {
		t.Error("Compare is not deterministic")
	}
}

func TestMarkdown_RendersAndEscapes(t *testing.T) {
	base := mkReport(nil, nil)
	cur := mkReport([]report.AssetView{av("a", "weird|name", classify.StatusShorBroken, 0.9, true)}, nil)
	out := Markdown(Compare(base, cur))
	if out == "" {
		t.Fatal("empty markdown")
	}
	if !contains(out, "Assessment diff") || !contains(out, "weird\\|name") {
		t.Errorf("markdown missing header or unescaped pipe:\n%s", out)
	}
}

func TestMarkdown_AllSections(t *testing.T) {
	base := mkReport(
		[]report.AssetView{
			av("a", "RSA", classify.StatusShorBroken, 0.8, true),         // changed below
			av("d", "DES", classify.StatusClassicallyBroken, 0.6, false), // removed
		},
		[]model.Finding{finding("R-OLD", "d", model.SeverityHigh)}, // resolved
	)
	cur := mkReport(
		[]report.AssetView{
			av("a", "RSA", classify.StatusShorBroken, 0.9, true),           // score regressed
			av("c", "ML-KEM", classify.StatusQuantumResistant, 0.1, false), // added
		},
		[]model.Finding{finding("R-NEW", "c", model.SeverityInfo)}, // added
	)
	out := Markdown(Compare(base, cur))

	for _, want := range []string{
		"## Risk changes", "regressed",
		"## New findings", "R-NEW",
		"## Resolved findings", "R-OLD",
		"## Assets added", "ML-KEM",
		"## Assets removed", "DES",
	} {
		if !contains(out, want) {
			t.Errorf("markdown missing %q:\n%s", want, out)
		}
	}
}

func TestMarkdown_NoChanges(t *testing.T) {
	r := mkReport([]report.AssetView{av("a", "RSA", classify.StatusShorBroken, 0.5, false)}, nil)
	out := Markdown(Compare(r, r))
	if !contains(out, "No changes between the two assessments.") {
		t.Errorf("expected a no-changes line:\n%s", out)
	}
}

func TestHNDLArrow(t *testing.T) {
	cases := []struct {
		from, to bool
		want     string
	}{
		{false, false, "no"},
		{true, true, "yes"},
		{false, true, "no → yes"},
		{true, false, "yes → no"},
	}
	for _, c := range cases {
		got := hndlArrow(AssetChange{FromHNDL: c.from, ToHNDL: c.to})
		if got != c.want {
			t.Errorf("hndlArrow(%v→%v) = %q, want %q", c.from, c.to, got, c.want)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
