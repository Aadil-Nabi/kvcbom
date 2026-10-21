package score

import (
	"math"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

func fptr(f float64) *float64 { return &f }

// ctx with one central scenario at Z years, one data class of X years, and one critical
// system that handles it. Migration time Y comes from the global default unless overridden.
func mkCtx(z, x, globalY float64, sysMigration *float64) *model.Context {
	return &model.Context{
		GlobalMigrationTimeYears: globalY,
		CRQCScenarios:            []model.CRQCScenario{{Name: "central", YearsUntil: z}},
		DataClasses:              []model.DataClass{{ID: "dc", Name: "DC", ConfidentialityLifetimeYears: x}},
		Systems: []model.System{{
			ID: "sys", Name: "Sys", Criticality: model.CriticalityCritical,
			DataClassRefs: []string{"dc"}, MigrationTimeYears: sysMigration,
		}},
	}
}

func linkedAsset() model.Asset {
	return model.Asset{
		ID: "a1", Name: "RSA-2048", Primitive: "pke",
		SystemRefs: []string{"sys"}, DataClassRefs: []string{"dc"},
		Evidence: []model.Evidence{{SourceType: model.SourceScannerCBOM, Confidence: model.C4}},
	}
}

func TestMosca_Boundary(t *testing.T) {
	w := defaultWeights
	// Z=10, Y=3 (global). Exposed requires X+Y > 10, i.e. X > 7.
	cases := []struct {
		x       float64
		exposed bool
	}{
		{6, false}, // 6+3=9 < 10
		{7, false}, // 7+3=10, not strictly greater
		{8, true},  // 8+3=11 > 10
	}
	for _, c := range cases {
		ctx := mkCtx(10, c.x, 3, nil)
		rs := Asset(linkedAsset(), classify.StatusShorBroken, ctx, w)
		if len(rs.MoscaExposure) != 1 {
			t.Fatalf("x=%v: expected one scenario result", c.x)
		}
		if rs.MoscaExposure[0].Exposed != c.exposed {
			t.Errorf("x=%v: exposed = %v, want %v (X+Y=%v, Z=10)",
				c.x, rs.MoscaExposure[0].Exposed, c.exposed, c.x+3)
		}
	}
}

func TestMosca_HNDL(t *testing.T) {
	ctx := mkCtx(10, 20, 3, nil) // long-lived data, well over the horizon
	// Shor-broken key establishment (pke) protecting long-lived data -> HNDL.
	rs := Asset(linkedAsset(), classify.StatusShorBroken, ctx, defaultWeights)
	if !rs.HNDL || !rs.MoscaExposure[0].HNDL {
		t.Errorf("expected HNDL exposure, got %+v", rs.MoscaExposure)
	}
	// A Grover-weakened symmetric cipher is exposed but not HNDL (not key establishment here).
	a := linkedAsset()
	a.Primitive = "block-cipher"
	rs = Asset(a, classify.StatusGroverWeakened, ctx, defaultWeights)
	if rs.HNDL {
		t.Error("grover-weakened block cipher should not be flagged HNDL")
	}
	if !rs.MoscaExposure[0].Exposed {
		t.Error("grover-weakened long-lived data should still be Mosca-exposed")
	}
}

func TestMosca_SystemMigrationOverride(t *testing.T) {
	ctx := mkCtx(10, 5, 3, fptr(6)) // system Y=6 overrides global 3; 5+6=11 > 10
	rs := Asset(linkedAsset(), classify.StatusShorBroken, ctx, defaultWeights)
	if rs.MoscaExposure[0].Y != 6 {
		t.Errorf("Y = %v, want the system override 6", rs.MoscaExposure[0].Y)
	}
	if !rs.MoscaExposure[0].Exposed {
		t.Error("expected exposure with the system migration override")
	}
}

func TestScore_NoContextNotesAndDefaults(t *testing.T) {
	a := model.Asset{ID: "a1", Name: "RSA", Evidence: []model.Evidence{{Confidence: model.C1}}}
	rs := Asset(a, classify.StatusShorBroken, nil, defaultWeights)
	if len(rs.MoscaExposure) != 0 {
		t.Error("no context should yield no Mosca results")
	}
	if rs.Criticality != model.CriticalityMedium.Weight() {
		t.Errorf("criticality = %v, want medium default", rs.Criticality)
	}
	if len(rs.Notes) == 0 {
		t.Error("expected explanatory notes when context is missing")
	}
}

func TestScore_QuantumWeights(t *testing.T) {
	cases := map[classify.QuantumStatus]float64{
		classify.StatusShorBroken:        1.0,
		classify.StatusClassicallyBroken: 1.0,
		classify.StatusGroverWeakened:    0.5,
		classify.StatusUnknown:           0.3,
		classify.StatusQuantumResistant:  0.0,
	}
	for status, want := range cases {
		rs := Asset(model.Asset{ID: "a"}, status, nil, defaultWeights)
		if rs.QuantumVulnerability != want {
			t.Errorf("%s: quantum weight = %v, want %v", status, rs.QuantumVulnerability, want)
		}
	}
}

func TestScore_FinalWeightedSum(t *testing.T) {
	ctx := mkCtx(10, 20, 3, nil) // exposed, mosca score 1.0
	rs := Asset(linkedAsset(), classify.StatusShorBroken, ctx, defaultWeights)
	// Q=1, mosca=1, crit=1 (crown... critical system), conf=1.0 (C4).
	// Final = 0.4*1 + 0.3*1 + 0.2*1 + 0.1*1.0 = 1.0.
	if math.Abs(rs.Final-1.0) > 1e-9 {
		t.Errorf("final = %v, want 1.0 (%s)", rs.Final, String(rs))
	}
}

func TestWeightsFrom(t *testing.T) {
	w := WeightsFrom(map[string]float64{
		"quantum_vulnerability": 0.5, "mosca_exposure": 0.2,
		"criticality": 0.2, "evidence_adjustment": 0.1,
	})
	if w.QuantumVulnerability != 0.5 || w.EvidenceConfidence != 0.1 {
		t.Errorf("unexpected weights: %+v", w)
	}
	// Missing keys fall back to defaults.
	w = WeightsFrom(map[string]float64{})
	if w != defaultWeights {
		t.Errorf("empty map should yield defaults, got %+v", w)
	}
}
