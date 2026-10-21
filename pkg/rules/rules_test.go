package rules

import (
	"reflect"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/pkg/rulepack"
)

func baseline(t *testing.T) *rulepack.Pack {
	t.Helper()
	lp, err := rulepack.LoadEmbedded("baseline-pqc")
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	return lp.Pack
}

func findingFor(res *Result, assetID string) *model.Finding {
	for i := range res.Findings {
		if res.Findings[i].AssetID == assetID {
			return &res.Findings[i]
		}
	}
	return nil
}

func TestEvaluate_BaselineFindings(t *testing.T) {
	p := baseline(t)
	assets := []model.Asset{
		{ID: "rsa", Name: "RSA-2048", OID: "1.2.840.113549.1.1.1", Primitive: "pke",
			Evidence: []model.Evidence{{SourceType: model.SourceScannerCBOM, Confidence: model.C3}}},
		{ID: "sha1", Name: "SHA-1", Evidence: []model.Evidence{{Confidence: model.C3}}},
		{ID: "aes128", Name: "AES-128-CBC", Evidence: []model.Evidence{{Confidence: model.C3}}},
		{ID: "mlkem", Name: "ML-KEM-768", Evidence: []model.Evidence{{Confidence: model.C3}}},
		{ID: "weird", Name: "Weirdo-512", Evidence: []model.Evidence{{Confidence: model.C3}}},
	}

	res, err := Evaluate(assets, p)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct {
		findingType string
		severity    model.Severity
	}{
		"rsa":    {"quantum-vulnerable-asymmetric", model.SeverityCritical},
		"sha1":   {"classically-broken-primitive", model.SeverityHigh},
		"aes128": {"symmetric-strength-reduced", model.SeverityMedium},
		"mlkem":  {"quantum-resistant-in-use", model.SeverityInfo},
		"weird":  {"unclassified-crypto-asset", model.SeverityInfo},
	}
	for id, want := range cases {
		f := findingFor(res, id)
		if f == nil {
			t.Errorf("%s: no finding produced", id)
			continue
		}
		if f.FindingType != want.findingType || f.Severity != want.severity {
			t.Errorf("%s: got %s/%s, want %s/%s", id, f.FindingType, f.Severity, want.findingType, want.severity)
		}
	}

	// Each asset triggers exactly one baseline rule (statuses are mutually exclusive).
	if len(res.Findings) != len(assets) {
		t.Errorf("finding count = %d, want %d (one per asset)", len(res.Findings), len(assets))
	}

	// Classifications are recorded for every asset.
	if len(res.Classifications) != len(assets) {
		t.Errorf("classification count = %d, want %d", len(res.Classifications), len(assets))
	}
}

func TestEvaluate_FindingsSortedBySeverity(t *testing.T) {
	p := baseline(t)
	assets := []model.Asset{
		{ID: "mlkem", Name: "ML-KEM-768"},
		{ID: "rsa", Name: "RSA-2048"},
	}
	res, err := Evaluate(assets, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) < 2 || res.Findings[0].Severity.Rank() > res.Findings[1].Severity.Rank() {
		t.Errorf("findings not sorted most-severe first: %+v", res.Findings)
	}
}

func TestEvaluate_RequiresVerification(t *testing.T) {
	p := baseline(t)
	assets := []model.Asset{
		{ID: "lowconf", Name: "RSA-2048", Evidence: []model.Evidence{{Confidence: model.C1}}},
		{ID: "highconf", Name: "RSA-2048", Evidence: []model.Evidence{{Confidence: model.C4}}},
	}
	res, err := Evaluate(assets, p)
	if err != nil {
		t.Fatal(err)
	}
	low := findingFor(res, "lowconf")
	high := findingFor(res, "highconf")
	if low == nil || high == nil {
		t.Fatal("expected findings for both assets")
	}
	if !low.RequiresVerification {
		t.Error("C1 evidence should flag requires_verification")
	}
	if high.RequiresVerification {
		t.Error("C4 evidence should not flag requires_verification")
	}
}

func TestEvaluate_EvidenceRefs(t *testing.T) {
	p := baseline(t)
	assets := []model.Asset{{
		ID: "rsa", Name: "RSA-2048",
		Evidence: []model.Evidence{{SourceType: model.SourceScannerCBOM, SourceFile: "bom.json", BOMRef: "alg:rsa", Confidence: model.C3}},
	}}
	res, err := Evaluate(assets, p)
	if err != nil {
		t.Fatal(err)
	}
	f := findingFor(res, "rsa")
	if f == nil || !reflect.DeepEqual(f.EvidenceRefs, []string{"bom.json#alg:rsa"}) {
		t.Errorf("evidence refs = %v", f.EvidenceRefs)
	}
}

func TestEvaluate_Deterministic(t *testing.T) {
	p := baseline(t)
	assets := []model.Asset{
		{ID: "b", Name: "AES-128"},
		{ID: "a", Name: "RSA-2048"},
		{ID: "c", Name: "SHA-1"},
	}
	r1, _ := Evaluate(assets, p)
	r2, _ := Evaluate(assets, p)
	if !reflect.DeepEqual(r1, r2) {
		t.Error("rule evaluation is not deterministic")
	}
}
