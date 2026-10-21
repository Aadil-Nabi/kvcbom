// Package diff compares two canonical reports to track progress between assessments
// (SPEC §4, §9): which assets appeared or disappeared, which changed quantum status or
// risk score, and which findings are new or resolved. It reads only Report structures, so
// a diff is deterministic and reproducible like the reports it consumes.
package diff

import (
	"sort"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/pkg/report"
)

// ReportMeta identifies one side of the comparison.
type ReportMeta struct {
	GeneratedAt string `json:"generated_at"`
	ToolVersion string `json:"tool_version"`
	PackID      string `json:"pack_id"`
	PackVersion string `json:"pack_version"`
	Assets      int    `json:"assets"`
	Findings    int    `json:"findings"`
}

// AssetRef is a compact reference to an asset in one report.
type AssetRef struct {
	AssetID       string  `json:"asset_id"`
	Name          string  `json:"name"`
	QuantumStatus string  `json:"quantum_status"`
	Final         float64 `json:"final_score"`
	HNDL          bool    `json:"hndl"`
}

// AssetChange records how an asset present in both reports changed.
type AssetChange struct {
	AssetID       string  `json:"asset_id"`
	Name          string  `json:"name"`
	FromStatus    string  `json:"from_status"`
	ToStatus      string  `json:"to_status"`
	FromFinal     float64 `json:"from_final_score"`
	ToFinal       float64 `json:"to_final_score"`
	FromHNDL      bool    `json:"from_hndl"`
	ToHNDL        bool    `json:"to_hndl"`
	StatusChanged bool    `json:"status_changed"`
	ScoreChanged  bool    `json:"score_changed"`
	Regressed     bool    `json:"regressed"` // score rose or HNDL newly set
}

// FindingRef is a compact reference to a finding.
type FindingRef struct {
	RuleID      string `json:"rule_id"`
	FindingType string `json:"finding_type"`
	Severity    string `json:"severity"`
	AssetID     string `json:"asset_id"`
	Title       string `json:"title"`
}

// Result is the full comparison, with every list sorted for deterministic output.
type Result struct {
	Baseline         ReportMeta    `json:"baseline"`
	Current          ReportMeta    `json:"current"`
	Summary          DiffSummary   `json:"summary"`
	AssetsAdded      []AssetRef    `json:"assets_added"`
	AssetsRemoved    []AssetRef    `json:"assets_removed"`
	AssetsChanged    []AssetChange `json:"assets_changed"`
	FindingsAdded    []FindingRef  `json:"findings_added"`
	FindingsResolved []FindingRef  `json:"findings_resolved"`
}

// DiffSummary tallies headline movement (severity counts kept as sorted slice for JSON).
type DiffSummary struct {
	AssetsAdded      int             `json:"assets_added"`
	AssetsRemoved    int             `json:"assets_removed"`
	AssetsChanged    int             `json:"assets_changed"`
	FindingsAdded    int             `json:"findings_added"`
	FindingsResolved int             `json:"findings_resolved"`
	NewFindingsBySev []SeverityCount `json:"new_findings_by_severity"`
}

// SeverityCount is a severity tally.
type SeverityCount struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

// Compare produces the diff of current relative to baseline.
func Compare(baseline, current *report.Report) *Result {
	res := &Result{
		Baseline: metaOf(baseline),
		Current:  metaOf(current),
	}

	baseAssets := indexAssets(baseline)
	curAssets := indexAssets(current)

	// Added / changed.
	for id, cur := range curAssets {
		base, ok := baseAssets[id]
		if !ok {
			res.AssetsAdded = append(res.AssetsAdded, refOf(cur))
			continue
		}
		if ch, changed := changeOf(base, cur); changed {
			res.AssetsChanged = append(res.AssetsChanged, ch)
		}
	}
	// Removed.
	for id, base := range baseAssets {
		if _, ok := curAssets[id]; !ok {
			res.AssetsRemoved = append(res.AssetsRemoved, refOf(base))
		}
	}

	// Findings keyed by rule+asset.
	baseFind := indexFindings(baseline)
	curFind := indexFindings(current)
	for k, f := range curFind {
		if _, ok := baseFind[k]; !ok {
			res.FindingsAdded = append(res.FindingsAdded, findingRef(f))
		}
	}
	for k, f := range baseFind {
		if _, ok := curFind[k]; !ok {
			res.FindingsResolved = append(res.FindingsResolved, findingRef(f))
		}
	}

	sortResult(res)
	res.Summary = summarise(res)
	return res
}

func metaOf(r *report.Report) ReportMeta {
	return ReportMeta{
		GeneratedAt: r.GeneratedAt, ToolVersion: r.Tool.Version,
		PackID: r.Pack.ID, PackVersion: r.Pack.Version,
		Assets: len(r.Assets), Findings: len(r.Findings),
	}
}

func indexAssets(r *report.Report) map[string]report.AssetView {
	m := make(map[string]report.AssetView, len(r.Assets))
	for _, av := range r.Assets {
		m[av.Asset.ID] = av
	}
	return m
}

func refOf(av report.AssetView) AssetRef {
	return AssetRef{
		AssetID: av.Asset.ID, Name: av.Asset.Name,
		QuantumStatus: string(av.Classification.Status), Final: av.Score.Final, HNDL: av.Score.HNDL,
	}
}

func changeOf(base, cur report.AssetView) (AssetChange, bool) {
	statusChanged := base.Classification.Status != cur.Classification.Status
	scoreChanged := base.Score.Final != cur.Score.Final
	hndlChanged := base.Score.HNDL != cur.Score.HNDL
	if !statusChanged && !scoreChanged && !hndlChanged {
		return AssetChange{}, false
	}
	return AssetChange{
		AssetID: cur.Asset.ID, Name: cur.Asset.Name,
		FromStatus: string(base.Classification.Status), ToStatus: string(cur.Classification.Status),
		FromFinal: base.Score.Final, ToFinal: cur.Score.Final,
		FromHNDL: base.Score.HNDL, ToHNDL: cur.Score.HNDL,
		StatusChanged: statusChanged, ScoreChanged: scoreChanged,
		Regressed: cur.Score.Final > base.Score.Final || (cur.Score.HNDL && !base.Score.HNDL),
	}, true
}

func indexFindings(r *report.Report) map[string]model.Finding {
	m := make(map[string]model.Finding, len(r.Findings))
	for _, f := range r.Findings {
		m[f.RuleID+"\x1f"+f.AssetID] = f
	}
	return m
}

func findingRef(f model.Finding) FindingRef {
	return FindingRef{
		RuleID: f.RuleID, FindingType: f.FindingType, Severity: string(f.Severity),
		AssetID: f.AssetID, Title: f.Title,
	}
}

func sortResult(res *Result) {
	sort.Slice(res.AssetsAdded, func(i, j int) bool { return res.AssetsAdded[i].AssetID < res.AssetsAdded[j].AssetID })
	sort.Slice(res.AssetsRemoved, func(i, j int) bool { return res.AssetsRemoved[i].AssetID < res.AssetsRemoved[j].AssetID })
	sort.Slice(res.AssetsChanged, func(i, j int) bool { return res.AssetsChanged[i].AssetID < res.AssetsChanged[j].AssetID })
	byFinding := func(a, b FindingRef) bool {
		if a.AssetID != b.AssetID {
			return a.AssetID < b.AssetID
		}
		return a.RuleID < b.RuleID
	}
	sort.Slice(res.FindingsAdded, func(i, j int) bool { return byFinding(res.FindingsAdded[i], res.FindingsAdded[j]) })
	sort.Slice(res.FindingsResolved, func(i, j int) bool { return byFinding(res.FindingsResolved[i], res.FindingsResolved[j]) })
}

func summarise(res *Result) DiffSummary {
	s := DiffSummary{
		AssetsAdded: len(res.AssetsAdded), AssetsRemoved: len(res.AssetsRemoved),
		AssetsChanged: len(res.AssetsChanged),
		FindingsAdded: len(res.FindingsAdded), FindingsResolved: len(res.FindingsResolved),
	}
	bySev := map[model.Severity]int{}
	for _, f := range res.FindingsAdded {
		bySev[model.Severity(f.Severity)]++
	}
	for _, sev := range []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo} {
		if n := bySev[sev]; n > 0 {
			s.NewFindingsBySev = append(s.NewFindingsBySev, SeverityCount{Severity: string(sev), Count: n})
		}
	}
	return s
}
