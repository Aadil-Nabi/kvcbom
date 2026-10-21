// Package report assembles the canonical assessment result from the engine's outputs and
// defines the Renderer interface the output formats implement. The JSON rendering of a
// Report is the single source of truth (SPEC §9): HTML, Markdown, and PDF are all rendered
// from the same structure, and `diff` consumes the JSON. Every collection is sorted so the
// serialised form is byte-identical across runs with the same inputs.
package report

import (
	"io"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/pkg/merge"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// SchemaVersion is the version of the canonical JSON output structure. It is independent
// of the tool and rule-pack versions (SPEC §10) and bumps when the shape changes.
const SchemaVersion = 1

// Renderer turns a Report into one output format.
type Renderer interface {
	Render(r *Report, w io.Writer) error
}

// PDFRenderer is a Renderer that produces PDF. Name identifies the engine; Available
// reports whether it can run in this environment (the Chromium engine needs a browser),
// returning a human-readable reason when it cannot.
type PDFRenderer interface {
	Renderer
	Name() string
	Available() (bool, string)
}

// Report is the canonical assessment result.
type Report struct {
	SchemaVersion  int                  `json:"schema_version"`
	Tool           ToolInfo             `json:"tool"`
	GeneratedAt    string               `json:"generated_at"`
	Title          string               `json:"title"`
	Assessment     model.AssessmentMeta `json:"assessment"`
	Pack           PackInfo             `json:"pack"`
	Inputs         []merge.InputHash    `json:"inputs"`
	Warnings       Warnings             `json:"warnings"`
	Summary        Summary              `json:"summary"`
	Inventory      Inventory            `json:"inventory"`
	Assets         []AssetView          `json:"assets"`
	FindingGroups  []FindingGroup       `json:"finding_groups"`
	AffectedAssets []AffectedAsset      `json:"affected_assets"`
	Findings       []model.Finding      `json:"findings"`
	Systems        []SystemView         `json:"systems"`
	Frameworks     []FrameworkView      `json:"frameworks,omitempty"`
	Remediation    []RemediationItem    `json:"remediation"`
	Appendix       Appendix             `json:"appendix"`
}

// ToolInfo identifies the tool build that produced the report.
type ToolInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// PackInfo identifies the rule pack used.
type PackInfo struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	Status     string `json:"status"`
	SHA256     string `json:"sha256"`
	Unverified bool   `json:"unverified_content"`
}

// Warnings surfaces caveats the reader must see before trusting the numbers (SPEC §9.2).
type Warnings struct {
	UnverifiedRuleContent bool     `json:"unverified_rule_content"`
	LowConfidenceCount    int      `json:"low_confidence_finding_count"`
	LowConfidenceShare    float64  `json:"low_confidence_finding_share"`
	Messages              []string `json:"messages,omitempty"`
}

// Count is a labelled tally used across the inventory and summary.
type Count struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// RiskRef points at a high-risk asset for the executive summary's "top risks".
type RiskRef struct {
	AssetID       string  `json:"asset_id"`
	Name          string  `json:"name"`
	QuantumStatus string  `json:"quantum_status"`
	Final         float64 `json:"final_score"`
	HNDL          bool    `json:"hndl"`
}

// ScenarioOutcome summarises Mosca exposure for one CRQC scenario.
type ScenarioOutcome struct {
	Scenario      string  `json:"scenario"`
	YearsUntil    float64 `json:"years_until_crqc"`
	ExposedAssets int     `json:"exposed_assets"`
	HNDLAssets    int     `json:"hndl_assets"`
}

// Summary is the one-page executive view (SPEC §9.3).
type Summary struct {
	TotalAssets     int               `json:"total_assets"`
	TotalFindings   int               `json:"total_findings"`
	FindingsBySev   []Count           `json:"findings_by_severity"`
	TopRisks        []RiskRef         `json:"top_risks"`
	HNDLAssetCount  int               `json:"hndl_asset_count"`
	MoscaByScenario []ScenarioOutcome `json:"mosca_by_scenario"`
}

// Inventory is the breakdown of what was found (SPEC §9.4).
type Inventory struct {
	ByType          []Count `json:"by_type"`
	ByQuantumStatus []Count `json:"by_quantum_status"`
	ByConfidence    []Count `json:"by_evidence_confidence"`
	BySystem        []Count `json:"by_system"`
}

// AssetView is one asset with its classification and score.
type AssetView struct {
	Asset          model.Asset     `json:"asset"`
	Classified     bool            `json:"classified"`
	Classification classify.Result `json:"classification"`
	Score          model.RiskScore `json:"score"`
}

// FindingGroup collapses all findings of one finding type into a single, readable entry
// for the report body: the shared severity/title/explanation, how many assets are
// affected, and the distinct affected asset names. The per-finding detail stays in
// Findings (and the JSON) for machine use and full traceability.
type FindingGroup struct {
	FindingType          string   `json:"finding_type"`
	Severity             string   `json:"severity"`
	Title                string   `json:"title"`
	Explanation          string   `json:"explanation,omitempty"`
	RemediationRef       string   `json:"remediation_ref,omitempty"`
	Count                int      `json:"count"`
	RequiresVerification int      `json:"requires_verification_count"`
	Assets               []string `json:"assets"`
}

// AffectedAsset is one actionable asset (a finding of medium severity or higher) with the
// detail an engineer needs to act: the algorithm, its quantum status, and where it was
// found. It drives the remediation-detail appendix so engineers need not open the JSON.
type AffectedAsset struct {
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	Severity  string   `json:"severity"`
	Primitive string   `json:"primitive,omitempty"`
	Count     int      `json:"count"` // how many occurrences (one algorithm at many endpoints)
	Locations []string `json:"locations,omitempty"`
}

// SystemView lists the assets and findings attributed to one business system.
type SystemView struct {
	System        model.System `json:"system"`
	AssetIDs      []string     `json:"asset_ids"`
	FindingCounts []Count      `json:"finding_counts"`
	WorstFinal    float64      `json:"worst_final_score"`
}

// FrameworkView echoes the pack's control framework and which finding types mapped to it.
type FrameworkView struct {
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Mappings []FrameworkMappingView `json:"mappings"`
}

// FrameworkMappingView is one finding-type → control mapping with its coverage count.
type FrameworkMappingView struct {
	FindingType  string `json:"finding_type"`
	ControlID    string `json:"control_id"`
	ControlTitle string `json:"control_title,omitempty"`
	Source       string `json:"source"`
	Unverified   bool   `json:"unverified"`
	FindingCount int    `json:"finding_count"`
}

// RemediationItem is remediation guidance plus which finding types and how many assets it
// applies to, ordered for the roadmap (SPEC §9.8).
type RemediationItem struct {
	ID           string   `json:"id"`
	Summary      string   `json:"summary"`
	Detail       string   `json:"detail,omitempty"`
	References   []string `json:"references,omitempty"`
	FindingTypes []string `json:"finding_types"`
	FindingCount int      `json:"finding_count"`
	TopSeverity  string   `json:"top_severity"`
}

// SourceView is a citation echoed into the appendix.
type SourceView struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	URL           string `json:"url"`
	Status        string `json:"status"`
	RetrievedDate string `json:"retrieved_date,omitempty"`
}

// Appendix carries methodology and traceability material (SPEC §9.9).
type Appendix struct {
	Methodology    string           `json:"methodology"`
	ScoringFormula string           `json:"scoring_formula"`
	Weights        model.Weights    `json:"weights"`
	MergeDecisions []merge.Decision `json:"merge_decisions"`
	Sources        []SourceView     `json:"sources"`
}
