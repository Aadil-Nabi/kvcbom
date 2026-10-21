package report

import (
	"fmt"
	"sort"
	"strings"

	ctxingest "github.com/Aadil-Nabi/kvcbom/pkg/ingest/context"
	"github.com/Aadil-Nabi/kvcbom/pkg/merge"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/pkg/rulepack"
	"github.com/Aadil-Nabi/kvcbom/pkg/rules"
	"github.com/Aadil-Nabi/kvcbom/pkg/score"
)

// Input is everything Build needs to assemble a Report. The caller (the CLI) performs the
// file reads and passes the parsed batches, context, and pack.
type Input struct {
	Title       string
	Assessment  model.AssessmentMeta
	Batches     []*model.Batch
	Context     *model.Context // optional
	Pack        *rulepack.Pack
	PackSHA256  string
	Tool        ToolInfo
	GeneratedAt string // injected RFC3339 timestamp (deterministic)

	// IngestWarnings are caveats raised while reading inputs (e.g. a CBOM that did not fully
	// conform to the schema, or a register header that could not be mapped). They are shown
	// in the report's Warnings section.
	IngestWarnings []string
}

// Build runs the assessment pipeline (merge → link → classify → rules → score) and
// assembles the canonical Report. It makes no network calls and reads no files.
func Build(in Input) (*Report, error) {
	merged := merge.Merge(in.Batches...)

	assets, err := ctxingest.Link(merged.Assets, in.Context)
	if err != nil {
		return nil, fmt.Errorf("link assets to context: %w", err)
	}

	eval, err := rules.Evaluate(assets, in.Pack)
	if err != nil {
		return nil, fmt.Errorf("evaluate rules: %w", err)
	}

	weights := score.WeightsFrom(in.Pack.Scoring().Weights)
	classByID := map[string]rules.AssetClassification{}
	for _, c := range eval.Classifications {
		classByID[c.AssetID] = c
	}

	title := in.Title
	if title == "" {
		title = "Post-Quantum Cryptographic Readiness Assessment"
	}

	rep := &Report{
		SchemaVersion: SchemaVersion,
		Tool:          in.Tool,
		GeneratedAt:   in.GeneratedAt,
		Title:         title,
		Assessment:    in.Assessment,
		Pack: PackInfo{
			ID: in.Pack.Meta().ID, Version: in.Pack.Meta().Version,
			Status: string(in.Pack.Meta().Status), SHA256: in.PackSHA256,
			Unverified: in.Pack.HasUnverifiedContent(),
		},
		Inputs:   merged.InputHashes,
		Findings: eval.Findings,
	}

	// Per-asset views and scores.
	for _, a := range assets {
		c := classByID[a.ID]
		rs := score.Asset(a, c.Result.Status, in.Context, weights)
		rep.Assets = append(rep.Assets, AssetView{
			Asset: a, Classified: c.Matched, Classification: c.Result, Score: rs,
		})
	}
	sort.Slice(rep.Assets, func(i, j int) bool { return rep.Assets[i].Asset.ID < rep.Assets[j].Asset.ID })

	rep.Summary = buildSummary(rep, in.Context)
	rep.Inventory = buildInventory(rep)
	rep.Systems = buildSystems(rep, in.Context)
	rep.Framework = buildFramework(in.Pack, rep.Findings)
	rep.Remediation = buildRemediation(in.Pack, rep.Findings)
	rep.Warnings = buildWarnings(rep, in.IngestWarnings)
	rep.Appendix = buildAppendix(in.Pack, merged.Decisions, weights)
	return rep, nil
}

func buildSummary(rep *Report, ctx *model.Context) Summary {
	s := Summary{TotalAssets: len(rep.Assets), TotalFindings: len(rep.Findings)}

	sevCount := map[model.Severity]int{}
	for _, f := range rep.Findings {
		sevCount[f.Severity]++
	}
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if n := sevCount[sev]; n > 0 {
			s.FindingsBySev = append(s.FindingsBySev, Count{Key: string(sev), Count: n})
		}
	}

	// Top risks: by final score desc, then asset id.
	ranked := append([]AssetView(nil), rep.Assets...)
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Score.Final != ranked[j].Score.Final {
			return ranked[i].Score.Final > ranked[j].Score.Final
		}
		return ranked[i].Asset.ID < ranked[j].Asset.ID
	})
	for _, av := range ranked {
		if av.Score.HNDL {
			s.HNDLAssetCount++
		}
	}
	for _, av := range ranked {
		if len(s.TopRisks) >= 5 || av.Score.Final <= 0 {
			break
		}
		s.TopRisks = append(s.TopRisks, RiskRef{
			AssetID: av.Asset.ID, Name: av.Asset.Name,
			QuantumStatus: string(av.Classification.Status), Final: av.Score.Final, HNDL: av.Score.HNDL,
		})
	}

	// Mosca per scenario, aggregated across assets.
	if ctx != nil && len(ctx.CRQCScenarios) > 0 {
		exposed := map[string]int{}
		hndl := map[string]int{}
		years := map[string]float64{}
		for _, sc := range ctx.CRQCScenarios {
			years[sc.Name] = sc.YearsUntil
		}
		for _, av := range rep.Assets {
			for _, m := range av.Score.MoscaExposure {
				if m.Exposed {
					exposed[m.Scenario]++
				}
				if m.HNDL {
					hndl[m.Scenario]++
				}
			}
		}
		names := make([]string, 0, len(years))
		for n := range years {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			s.MoscaByScenario = append(s.MoscaByScenario, ScenarioOutcome{
				Scenario: n, YearsUntil: years[n], ExposedAssets: exposed[n], HNDLAssets: hndl[n],
			})
		}
	}
	return s
}

func buildInventory(rep *Report) Inventory {
	byType := map[string]int{}
	byStatus := map[string]int{}
	byConf := map[string]int{}
	bySystem := map[string]int{}
	for _, av := range rep.Assets {
		byType[string(av.Asset.Type)]++
		byStatus[string(av.Classification.Status)]++
		byConf[maxConfidence(av.Asset).String()]++
		if len(av.Asset.SystemRefs) == 0 {
			bySystem["(unlinked)"]++
		}
		for _, sys := range av.Asset.SystemRefs {
			bySystem[sys]++
		}
	}
	return Inventory{
		ByType:          toCounts(byType),
		ByQuantumStatus: toCounts(byStatus),
		ByConfidence:    toCounts(byConf),
		BySystem:        toCounts(bySystem),
	}
}

func buildSystems(rep *Report, ctx *model.Context) []SystemView {
	if ctx == nil {
		return nil
	}
	findingsByAsset := map[string][]model.Finding{}
	for _, f := range rep.Findings {
		findingsByAsset[f.AssetID] = append(findingsByAsset[f.AssetID], f)
	}

	var views []SystemView
	for _, sys := range ctx.Systems {
		sv := SystemView{System: sys}
		sevCount := map[model.Severity]int{}
		for _, av := range rep.Assets {
			if !contains(av.Asset.SystemRefs, sys.ID) {
				continue
			}
			sv.AssetIDs = append(sv.AssetIDs, av.Asset.ID)
			if av.Score.Final > sv.WorstFinal {
				sv.WorstFinal = av.Score.Final
			}
			for _, f := range findingsByAsset[av.Asset.ID] {
				sevCount[f.Severity]++
			}
		}
		sort.Strings(sv.AssetIDs)
		for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
			if n := sevCount[sev]; n > 0 {
				sv.FindingCounts = append(sv.FindingCounts, Count{Key: string(sev), Count: n})
			}
		}
		views = append(views, sv)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].System.ID < views[j].System.ID })
	return views
}

func buildFramework(p *rulepack.Pack, findings []model.Finding) *FrameworkView {
	fw := p.Framework()
	if fw.ID == "" {
		return nil
	}
	countByType := map[string]int{}
	for _, f := range findings {
		countByType[f.FindingType]++
	}
	view := &FrameworkView{ID: fw.ID, Name: fw.Name}
	for _, m := range fw.Mappings {
		view.Mappings = append(view.Mappings, FrameworkMappingView{
			FindingType: m.FindingType, ControlID: m.ControlID, ControlTitle: m.ControlTitle,
			Source: m.Source, FindingCount: countByType[m.FindingType],
			Unverified: containsTODO(m.ControlID) || containsTODO(m.ControlTitle),
		})
	}
	sort.Slice(view.Mappings, func(i, j int) bool {
		if view.Mappings[i].FindingType != view.Mappings[j].FindingType {
			return view.Mappings[i].FindingType < view.Mappings[j].FindingType
		}
		return view.Mappings[i].ControlID < view.Mappings[j].ControlID
	})
	return view
}

func buildRemediation(p *rulepack.Pack, findings []model.Finding) []RemediationItem {
	type agg struct {
		types       map[string]struct{}
		count       int
		topSeverity model.Severity
	}
	byRef := map[string]*agg{}
	for _, f := range findings {
		if f.RemediationRef == "" {
			continue
		}
		a := byRef[f.RemediationRef]
		if a == nil {
			a = &agg{types: map[string]struct{}{}, topSeverity: model.SeverityInfo}
			byRef[f.RemediationRef] = a
		}
		a.types[f.FindingType] = struct{}{}
		a.count++
		if f.Severity.Rank() < a.topSeverity.Rank() {
			a.topSeverity = f.Severity
		}
	}

	var items []RemediationItem
	for ref, a := range byRef {
		rem, ok := p.Remediation(ref)
		if !ok {
			continue
		}
		items = append(items, RemediationItem{
			ID: rem.ID, Summary: rem.Summary, Detail: rem.Detail, References: rem.References,
			FindingTypes: sortedSet(a.types), FindingCount: a.count, TopSeverity: string(a.topSeverity),
		})
	}
	// Roadmap order: most severe first, then most findings, then id.
	sort.Slice(items, func(i, j int) bool {
		ri, rj := model.Severity(items[i].TopSeverity).Rank(), model.Severity(items[j].TopSeverity).Rank()
		if ri != rj {
			return ri < rj
		}
		if items[i].FindingCount != items[j].FindingCount {
			return items[i].FindingCount > items[j].FindingCount
		}
		return items[i].ID < items[j].ID
	})
	return items
}

func buildWarnings(rep *Report, ingestWarnings []string) Warnings {
	w := Warnings{UnverifiedRuleContent: rep.Pack.Unverified}
	w.Messages = append(w.Messages, ingestWarnings...)
	for _, f := range rep.Findings {
		if f.RequiresVerification {
			w.LowConfidenceCount++
		}
	}
	if len(rep.Findings) > 0 {
		w.LowConfidenceShare = float64(w.LowConfidenceCount) / float64(len(rep.Findings))
	}
	if w.UnverifiedRuleContent {
		w.Messages = append(w.Messages, "the rule pack contains unverified content (draft/vendor status or TODO(source) placeholders); verify cited controls before relying on them")
	}
	if w.LowConfidenceCount > 0 {
		w.Messages = append(w.Messages, fmt.Sprintf("%d finding(s) rest on low-confidence evidence (C1/C2) and are marked as requiring verification", w.LowConfidenceCount))
	}
	unclassified := 0
	for _, av := range rep.Assets {
		if !av.Classified {
			unclassified++
		}
	}
	if unclassified > 0 {
		w.Messages = append(w.Messages, fmt.Sprintf("%d asset(s) could not be classified from the available data", unclassified))
	}
	return w
}

func buildAppendix(p *rulepack.Pack, decisions []merge.Decision, w model.Weights) Appendix {
	ap := Appendix{
		Methodology: "Assets are ingested from CycloneDX 1.6 CBOMs and any manual register, " +
			"deduplicated by a deterministic identity, linked to business systems and data " +
			"classes from the context file, classified for quantum vulnerability using the rule " +
			"pack, and scored. The Mosca inequality (X + Y > Z) compares how long data must stay " +
			"secret (X, confidentiality lifetime) plus the time to migrate (Y) against the years " +
			"until a cryptographically relevant quantum computer (Z), per user-supplied scenario. " +
			"Harvest-now-decrypt-later (HNDL) marks Shor-broken key establishment or encryption " +
			"over data that outlives Z.",
		ScoringFormula: fmt.Sprintf(
			"final = (%.2f*quantum_vulnerability + %.2f*mosca_exposure + %.2f*criticality + %.2f*evidence_confidence) / sum_of_weights; all terms in [0,1]",
			w.QuantumVulnerability, w.MoscaExposure, w.Criticality, w.EvidenceConfidence),
		Weights:        w,
		MergeDecisions: decisions,
	}
	if ap.MergeDecisions == nil {
		ap.MergeDecisions = []merge.Decision{}
	}
	for _, s := range p.Sources() {
		ap.Sources = append(ap.Sources, SourceView{
			ID: s.ID, Title: s.Title, URL: s.URL, Status: string(s.Status), RetrievedDate: s.RetrievedDate,
		})
	}
	return ap
}

// --- helpers ---

func toCounts(m map[string]int) []Count {
	out := make([]Count, 0, len(m))
	for k, v := range m {
		out = append(out, Count{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	return out
}

func sortedSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func containsTODO(s string) bool { return strings.Contains(s, rulepack.TODOMarker) }
