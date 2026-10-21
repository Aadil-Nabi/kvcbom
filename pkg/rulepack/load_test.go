package rulepack

import (
	"reflect"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

func ptr(i int) *int { return &i }

func loadBaseline(t *testing.T) *Pack {
	t.Helper()
	lp, err := LoadEmbedded("baseline-pqc")
	if err != nil {
		t.Fatalf("LoadEmbedded(baseline-pqc): %v", err)
	}
	return lp.Pack
}

func TestBaseline_LoadsAndValidatesClean(t *testing.T) {
	p := loadBaseline(t)
	if issues := p.Validate(); len(issues) != 0 {
		t.Fatalf("baseline should validate with no issues, got: %v", issues)
	}
	if p.HasUnverifiedContent() {
		t.Error("baseline (final, no TODO) should not be flagged as unverified")
	}
	if p.Meta().ID != "baseline-pqc" || p.Meta().Status != StatusFinal {
		t.Errorf("unexpected meta: %+v", p.Meta())
	}
}

func TestBaseline_Classification(t *testing.T) {
	p := loadBaseline(t)

	cases := []struct {
		name  string
		asset model.Asset
		want  classify.QuantumStatus
	}{
		{"RSA by OID", model.Asset{Name: "RSA-2048", OID: "1.2.840.113549.1.1.1"}, classify.StatusShorBroken},
		{"RSA by name", model.Asset{Name: "RSASSA-PSS"}, classify.StatusShorBroken},
		{"ECDSA", model.Asset{Name: "ECDSA P-256"}, classify.StatusShorBroken},
		{"Ed25519", model.Asset{Name: "Ed25519"}, classify.StatusShorBroken},
		{"DSA", model.Asset{Name: "DSA-2048"}, classify.StatusShorBroken},
		{"DH", model.Asset{Name: "Diffie-Hellman"}, classify.StatusShorBroken},
		{"X25519 by name", model.Asset{Name: "X25519"}, classify.StatusShorBroken},
		{"EC by curve only", model.Asset{Curve: "P-384"}, classify.StatusShorBroken},
		{"ML-KEM", model.Asset{Name: "ML-KEM-768"}, classify.StatusQuantumResistant},
		{"Kyber", model.Asset{Name: "Kyber512"}, classify.StatusQuantumResistant},
		{"ML-DSA (not DSA)", model.Asset{Name: "ML-DSA-65"}, classify.StatusQuantumResistant},
		{"SLH-DSA (not DSA)", model.Asset{Name: "SLH-DSA-SHA2-128s"}, classify.StatusQuantumResistant},
		{"AES-256-GCM by name", model.Asset{Name: "AES-256-GCM"}, classify.StatusQuantumResistant},
		{"AES-128 by name", model.Asset{Name: "AES-128-CBC"}, classify.StatusGroverWeakened},
		{"AES-256 by keysize", model.Asset{Name: "AES", KeySizeBits: ptr(256)}, classify.StatusQuantumResistant},
		{"AES-128 by keysize", model.Asset{Name: "AES", KeySizeBits: ptr(128)}, classify.StatusGroverWeakened},
		{"AES no size", model.Asset{Name: "AES"}, classify.StatusGroverWeakened},
		{"SHA-256", model.Asset{Name: "SHA-256"}, classify.StatusQuantumResistant},
		{"SHA3-512", model.Asset{Name: "SHA3-512"}, classify.StatusQuantumResistant},
		{"SHA-1", model.Asset{Name: "SHA-1"}, classify.StatusClassicallyBroken},
		{"MD5", model.Asset{Name: "MD5"}, classify.StatusClassicallyBroken},
		{"3DES", model.Asset{Name: "3DES-EDE-CBC"}, classify.StatusClassicallyBroken},
		{"RC4", model.Asset{Name: "RC4"}, classify.StatusClassicallyBroken},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, ok := p.Classify(c.asset)
			if !ok {
				t.Fatalf("%s: expected a classification, got none", c.name)
			}
			if res.Status != c.want {
				t.Errorf("%s: status = %q (entry %q), want %q", c.name, res.Status, res.EntryID, c.want)
			}
			if res.SourceID == "" {
				t.Errorf("%s: classification carries no source reference", c.name)
			}
		})
	}
}

func TestBaseline_UnmatchedIsUnknown(t *testing.T) {
	p := loadBaseline(t)
	// A protocol asset is not an algorithm and should not be classified by baseline.
	if res, ok := p.Classify(model.Asset{Name: "tls", Type: model.AssetProtocol}); ok {
		t.Errorf("protocol should be unknown, got %q via %q", res.Status, res.EntryID)
	}
}

func TestBaseline_ClassificationCarriesProvenance(t *testing.T) {
	p := loadBaseline(t)
	res, _ := p.Classify(model.Asset{Name: "RSA-2048", OID: "1.2.840.113549.1.1.1"})
	if res.PackID != "baseline-pqc" || res.PackVersion != "1.0.0" {
		t.Errorf("result missing pack provenance: %+v", res)
	}
	if res.EntryID == "" || len(res.MatchedBy) == 0 {
		t.Errorf("result missing entry/matched-by: %+v", res)
	}
}

func TestBaseline_Deterministic(t *testing.T) {
	a := loadBaseline(t)
	b := loadBaseline(t)
	asset := model.Asset{Name: "ECDSA", Curve: "P-256"}
	ra, _ := a.Classify(asset)
	rb, _ := b.Classify(asset)
	if !reflect.DeepEqual(ra, rb) {
		t.Errorf("classification differs across loads: %+v vs %+v", ra, rb)
	}
}

func TestList_IncludesBaseline(t *testing.T) {
	metas, err := List()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range metas {
		if m.ID == "baseline-pqc" {
			found = true
		}
	}
	if !found {
		t.Error("List did not include baseline-pqc")
	}
}

func TestLoad_UnknownIDFails(t *testing.T) {
	if _, err := Load("no-such-pack"); err == nil {
		t.Fatal("expected an error for an unknown pack id")
	}
}
