package rulepack

import (
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/rulepacks"
)

// TestEmbeddedPacks_LoadAndValidateWithoutErrors asserts every shipped pack loads and has
// no validation errors (TODO warnings are allowed for the structure-only packs).
func TestEmbeddedPacks_LoadAndValidateWithoutErrors(t *testing.T) {
	names := rulepacks.Names()
	if len(names) < 4 {
		t.Fatalf("expected at least 4 embedded packs, got %v", names)
	}
	for _, id := range names {
		t.Run(id, func(t *testing.T) {
			lp, err := LoadEmbedded(id)
			if err != nil {
				t.Fatalf("load %s: %v", id, err)
			}
			if err := ValidationError(lp.Pack.Validate()); err != nil {
				t.Errorf("%s has validation errors: %v", id, err)
			}
		})
	}
}

func TestFrameworkPacks_UnverifiedAndMapped(t *testing.T) {
	for _, id := range []string{"nist-ir-8547", "cnsa-2.0", "csa-qri-sg"} {
		t.Run(id, func(t *testing.T) {
			lp, err := LoadEmbedded(id)
			if err != nil {
				t.Fatal(err)
			}
			p := lp.Pack
			if !p.HasUnverifiedContent() {
				t.Errorf("%s is structure-only and must report unverified content", id)
			}
			if fw := p.Framework(); fw.ID == "" || len(fw.Mappings) == 0 {
				t.Errorf("%s should define a framework with mappings, got %+v", id, fw)
			}
			// It still classifies the basics from real sources.
			if res, ok := p.Classify(model.Asset{Name: "RSA-2048"}); !ok || res.Status != classify.StatusShorBroken {
				t.Errorf("%s: RSA should classify shor_broken, got %q ok=%v", id, res.Status, ok)
			}
			if res, ok := p.Classify(model.Asset{Name: "ML-KEM-768"}); !ok || res.Status != classify.StatusQuantumResistant {
				t.Errorf("%s: ML-KEM should classify quantum_resistant, got %q", id, res.Status)
			}
		})
	}
}

func TestBaselinePack_Verified(t *testing.T) {
	lp, err := LoadEmbedded("baseline-pqc")
	if err != nil {
		t.Fatal(err)
	}
	if lp.Pack.HasUnverifiedContent() {
		t.Error("baseline-pqc is final with no TODO markers and must not be flagged unverified")
	}
}
