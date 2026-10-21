// Package score computes a per-asset risk score from four components (SPEC §6, §8):
// quantum vulnerability (from the classification), Mosca exposure (X+Y>Z per CRQC
// scenario, with harvest-now-decrypt-later detection), business criticality (from the
// context), and evidence confidence. The final value is a weighted sum in [0,1] using the
// rule pack's weights; every component is returned alongside it so no number is opaque.
package score

import (
	"fmt"
	"sort"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// Default weights, used when a pack omits a weight (SPEC §8 keeps them configurable).
var defaultWeights = model.Weights{
	QuantumVulnerability: 0.4,
	MoscaExposure:        0.3,
	Criticality:          0.2,
	EvidenceConfidence:   0.1,
}

// WeightsFrom reads scoring weights from a pack's weight map, falling back to the defaults
// for any missing key. Both "evidence_confidence" and the legacy "evidence_adjustment"
// key are accepted for the evidence weight.
func WeightsFrom(m map[string]float64) model.Weights {
	w := defaultWeights
	if v, ok := m["quantum_vulnerability"]; ok {
		w.QuantumVulnerability = v
	}
	if v, ok := m["mosca_exposure"]; ok {
		w.MoscaExposure = v
	}
	if v, ok := m["criticality"]; ok {
		w.Criticality = v
	}
	if v, ok := m["evidence_confidence"]; ok {
		w.EvidenceConfidence = v
	} else if v, ok := m["evidence_adjustment"]; ok {
		w.EvidenceConfidence = v
	}
	return w
}

// Asset scores one asset given its quantum status and (optional) business context.
func Asset(a model.Asset, status classify.QuantumStatus, ctx *model.Context, w model.Weights) model.RiskScore {
	rs := model.RiskScore{
		QuantumVulnerability: quantumWeight(status),
		EvidenceConfidence:   confidenceWeight(maxConfidence(a)),
		Weights:              w,
	}

	rs.Criticality = criticality(a, ctx, &rs)
	rs.MoscaExposure, rs.MoscaScore, rs.HNDL = mosca(a, status, ctx, &rs)

	sum := w.QuantumVulnerability + w.MoscaExposure + w.Criticality + w.EvidenceConfidence
	if sum == 0 {
		sum = 1
	}
	rs.Final = (w.QuantumVulnerability*rs.QuantumVulnerability +
		w.MoscaExposure*rs.MoscaScore +
		w.Criticality*rs.Criticality +
		w.EvidenceConfidence*rs.EvidenceConfidence) / sum
	return rs
}

func quantumWeight(s classify.QuantumStatus) float64 {
	switch s {
	case classify.StatusShorBroken, classify.StatusClassicallyBroken:
		return 1.0
	case classify.StatusGroverWeakened:
		return 0.5
	case classify.StatusUnknown:
		return 0.3 // uncertain, not zero — an unclassified asset still warrants attention
	case classify.StatusQuantumResistant:
		return 0.0
	default:
		return 0.3
	}
}

func confidenceWeight(c model.ConfLevel) float64 {
	switch c {
	case model.C1:
		return 0.25
	case model.C2:
		return 0.5
	case model.C3:
		return 0.75
	case model.C4:
		return 1.0
	default:
		return 0.25
	}
}

func maxConfidence(a model.Asset) model.ConfLevel {
	best := model.C1
	for _, e := range a.Evidence {
		if e.Confidence > best {
			best = e.Confidence
		}
	}
	return best
}

// criticality returns the business-criticality component in [0,1], noting when it had to
// fall back to a default because no system was linked.
func criticality(a model.Asset, ctx *model.Context, rs *model.RiskScore) float64 {
	if ctx == nil || len(a.SystemRefs) == 0 {
		rs.Notes = append(rs.Notes, "no linked system; criticality defaulted to medium")
		return model.CriticalityMedium.Weight()
	}
	best := 0.0
	for _, id := range a.SystemRefs {
		sys, ok := ctx.SystemByID(id)
		if !ok {
			continue
		}
		w := sys.Criticality.Weight()
		if sys.CrownJewel {
			w = model.CriticalityCritical.Weight()
		}
		if w > best {
			best = w
		}
	}
	if best == 0 {
		rs.Notes = append(rs.Notes, "linked systems not found in context; criticality defaulted to medium")
		return model.CriticalityMedium.Weight()
	}
	return best
}

// mosca evaluates X+Y>Z for every CRQC scenario. It is computed only when the asset is
// linked to at least one data class (so X is known) and scenarios are defined; otherwise
// it returns no results and records why.
func mosca(a model.Asset, status classify.QuantumStatus, ctx *model.Context, rs *model.RiskScore) ([]model.MoscaResult, float64, bool) {
	if ctx == nil || len(ctx.CRQCScenarios) == 0 {
		rs.Notes = append(rs.Notes, "no CRQC scenarios; Mosca exposure not computed")
		return nil, 0, false
	}
	x, haveX := confidentialityLifetime(a, ctx)
	if !haveX {
		rs.Notes = append(rs.Notes, "no linked data class; Mosca exposure not computed")
		return nil, 0, false
	}
	y := migrationTime(a, ctx)

	vulnerable := status == classify.StatusShorBroken || status == classify.StatusGroverWeakened
	hndlCapable := status == classify.StatusShorBroken && protectsConfidentiality(a)

	scenarios := append([]model.CRQCScenario(nil), ctx.CRQCScenarios...)
	sort.Slice(scenarios, func(i, j int) bool { return scenarios[i].Name < scenarios[j].Name })

	var results []model.MoscaResult
	exposedCount := 0
	anyHNDL := false
	for _, sc := range scenarios {
		timelineExceeded := x+y > sc.YearsUntil
		exposed := timelineExceeded && vulnerable
		hndl := exposed && hndlCapable
		if exposed {
			exposedCount++
		}
		if hndl {
			anyHNDL = true
		}
		results = append(results, model.MoscaResult{
			Scenario: sc.Name, X: x, Y: y, Z: sc.YearsUntil, Exposed: exposed, HNDL: hndl,
		})
	}
	return results, float64(exposedCount) / float64(len(results)), anyHNDL
}

func confidentialityLifetime(a model.Asset, ctx *model.Context) (float64, bool) {
	best := 0.0
	found := false
	for _, id := range a.DataClassRefs {
		dc, ok := ctx.DataClassByID(id)
		if !ok {
			continue
		}
		found = true
		if dc.ConfidentialityLifetimeYears > best {
			best = dc.ConfidentialityLifetimeYears
		}
	}
	return best, found
}

func migrationTime(a model.Asset, ctx *model.Context) float64 {
	best := -1.0
	for _, id := range a.SystemRefs {
		sys, ok := ctx.SystemByID(id)
		if !ok || sys.MigrationTimeYears == nil {
			continue
		}
		if *sys.MigrationTimeYears > best {
			best = *sys.MigrationTimeYears
		}
	}
	if best < 0 {
		return ctx.GlobalMigrationTimeYears
	}
	return best
}

// protectsConfidentiality reports whether the asset performs key establishment or
// encryption — the mechanisms whose capture enables harvest-now-decrypt-later.
func protectsConfidentiality(a model.Asset) bool {
	switch a.Primitive {
	case "pke", "kem", "key-agree":
		return true
	}
	for _, fn := range a.Functions {
		switch fn {
		case "encrypt", "encapsulate", "keyderive", "keygen":
			return true
		}
	}
	return false
}

// String is a convenience for debugging/logging a score succinctly.
func String(rs model.RiskScore) string {
	return fmt.Sprintf("final=%.3f q=%.2f mosca=%.2f crit=%.2f conf=%.2f hndl=%v",
		rs.Final, rs.QuantumVulnerability, rs.MoscaScore, rs.Criticality, rs.EvidenceConfidence, rs.HNDL)
}
