package merge

import (
	"reflect"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

func ev(src model.SourceType, file, ref string, c model.ConfLevel) model.Evidence {
	return model.Evidence{SourceType: src, SourceFile: file, BOMRef: ref, Confidence: c}
}

func TestMerge_DeduplicatesAndMergesEvidence(t *testing.T) {
	b1 := &model.Batch{SourceFile: "a.json", SourceSHA256: "aaa", Assets: []model.Asset{
		{ID: "x", Name: "RSA-2048", Locations: []string{"src/a.go"},
			Evidence: []model.Evidence{ev(model.SourceScannerCBOM, "a.json", "alg:rsa", model.C2)}},
	}}
	b2 := &model.Batch{SourceFile: "reg.csv", SourceSHA256: "bbb", Assets: []model.Asset{
		{ID: "x", Name: "RSA-2048", Locations: []string{"src/b.go"}, SystemRefs: []string{"payments"},
			Evidence: []model.Evidence{ev(model.SourceManualRegister, "reg.csv", "", model.C1)}},
		{ID: "y", Name: "AES-256", Evidence: []model.Evidence{ev(model.SourceScannerCBOM, "reg.csv", "alg:aes", model.C2)}},
	}}

	res := Merge(b1, b2)

	if len(res.Assets) != 2 {
		t.Fatalf("asset count = %d, want 2", len(res.Assets))
	}
	// x merged.
	var x *model.Asset
	for i := range res.Assets {
		if res.Assets[i].ID == "x" {
			x = &res.Assets[i]
		}
	}
	if x == nil {
		t.Fatal("merged asset x not found")
	}
	if len(x.Evidence) != 2 {
		t.Errorf("x evidence = %d, want 2 merged", len(x.Evidence))
	}
	if !reflect.DeepEqual(x.Locations, []string{"src/a.go", "src/b.go"}) {
		t.Errorf("x locations = %v, want union sorted", x.Locations)
	}
	if !reflect.DeepEqual(x.SystemRefs, []string{"payments"}) {
		t.Errorf("x system refs = %v", x.SystemRefs)
	}

	// Exactly one decision, for x.
	if len(res.Decisions) != 1 || res.Decisions[0].AssetID != "x" {
		t.Fatalf("decisions = %+v, want one for x", res.Decisions)
	}
	if !reflect.DeepEqual(res.Decisions[0].Sources, []string{"a.json#alg:rsa", "reg.csv"}) {
		t.Errorf("decision sources = %v", res.Decisions[0].Sources)
	}

	// Input hashes for both files.
	if len(res.InputHashes) != 2 {
		t.Errorf("input hashes = %v, want 2", res.InputHashes)
	}
}

func TestMerge_OrderIndependentAndDeterministic(t *testing.T) {
	b1 := &model.Batch{SourceFile: "a.json", SourceSHA256: "a", Assets: []model.Asset{
		{ID: "x", Name: "RSA", Evidence: []model.Evidence{ev(model.SourceScannerCBOM, "a.json", "r1", model.C2)}},
		{ID: "z", Name: "DSA", Evidence: []model.Evidence{ev(model.SourceScannerCBOM, "a.json", "r3", model.C2)}},
	}}
	b2 := &model.Batch{SourceFile: "b.json", SourceSHA256: "b", Assets: []model.Asset{
		{ID: "x", Name: "RSA", Evidence: []model.Evidence{ev(model.SourceScannerCBOM, "b.json", "r2", model.C3)}},
		{ID: "y", Name: "AES", Evidence: []model.Evidence{ev(model.SourceScannerCBOM, "b.json", "r4", model.C2)}},
	}}

	r1 := Merge(b1, b2)
	r2 := Merge(b2, b1)
	if !reflect.DeepEqual(r1, r2) {
		t.Error("merge is not order-independent")
	}

	// Assets sorted by ID.
	ids := []string{r1.Assets[0].ID, r1.Assets[1].ID, r1.Assets[2].ID}
	if !reflect.DeepEqual(ids, []string{"x", "y", "z"}) {
		t.Errorf("assets not sorted by id: %v", ids)
	}
}

func TestMerge_NoDecisionForSingleSource(t *testing.T) {
	b := &model.Batch{SourceFile: "a.json", Assets: []model.Asset{
		{ID: "x", Name: "RSA", Evidence: []model.Evidence{ev(model.SourceScannerCBOM, "a.json", "r1", model.C2)}},
	}}
	res := Merge(b)
	if len(res.Decisions) != 0 {
		t.Errorf("expected no merge decisions for a single-source asset, got %v", res.Decisions)
	}
}

func TestMerge_DuplicateEvidenceCollapsed(t *testing.T) {
	// The same evidence record appearing in two batches must not duplicate.
	e := ev(model.SourceScannerCBOM, "a.json", "r1", model.C2)
	b1 := &model.Batch{SourceFile: "a.json", Assets: []model.Asset{{ID: "x", Name: "RSA", Evidence: []model.Evidence{e}}}}
	b2 := &model.Batch{SourceFile: "a.json", Assets: []model.Asset{{ID: "x", Name: "RSA", Evidence: []model.Evidence{e}}}}
	res := Merge(b1, b2)
	if len(res.Assets[0].Evidence) != 1 {
		t.Errorf("identical evidence should collapse to 1, got %d", len(res.Assets[0].Evidence))
	}
}
