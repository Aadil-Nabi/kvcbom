package rulepack

import (
	"testing"

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

func TestFrameworkOverlays_MappedAndClassifierless(t *testing.T) {
	// The canonical finding-type vocabulary a classifier emits; overlays map these.
	wantTypes := map[string]bool{
		"quantum-vulnerable-key-establishment": true,
		"quantum-vulnerable-signature":         true,
		"classically-broken-primitive":         true,
		"symmetric-strength-reduced":           true,
	}
	for _, id := range []string{"nist-ir-8547", "cnsa-2.0", "csa-qri-sg", "enisa-eu", "uk-ncsc"} {
		t.Run(id, func(t *testing.T) {
			lp, err := LoadEmbedded(id)
			if err != nil {
				t.Fatal(err)
			}
			p := lp.Pack
			if !p.HasUnverifiedContent() {
				t.Errorf("%s is a structure-only overlay and must report unverified content", id)
			}
			// An overlay has no classification table of its own.
			if len(p.ClassificationEntries()) != 0 {
				t.Errorf("%s is an overlay and should carry no classifications", id)
			}
			fw := p.Framework()
			if fw.ID == "" || len(fw.Mappings) == 0 {
				t.Fatalf("%s should define a framework with mappings, got %+v", id, fw)
			}
			// Every mapping targets a finding type in the canonical vocabulary.
			for _, m := range fw.Mappings {
				if !wantTypes[m.FindingType] {
					t.Errorf("%s maps unknown finding type %q", id, m.FindingType)
				}
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
