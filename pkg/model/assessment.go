package model

// Severity grades a finding, highest to lowest. It mirrors the rule-pack vocabulary but
// lives in the model so downstream packages need not import the rule-pack package.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rank orders severities for sorting (0 = most severe).
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	default:
		return 5
	}
}

// FrameworkRef is a finding's mapping to a control in a compliance framework. Unverified
// is true when the control identifier/title was an unfilled TODO(source) placeholder, so
// the report can mark it as not yet verified.
type FrameworkRef struct {
	ControlID    string `json:"control_id"`
	ControlTitle string `json:"control_title,omitempty"`
	Source       string `json:"source"`
	Unverified   bool   `json:"unverified"`
}

// Finding is a single risk raised by a rule against an asset. Every field needed to trace
// it back to its origin is present (SPEC §3.4): the rule id, the asset, and the evidence.
type Finding struct {
	RuleID               string         `json:"rule_id"`
	FindingType          string         `json:"finding_type"`
	Severity             Severity       `json:"severity"`
	AssetID              string         `json:"asset_id"`
	Title                string         `json:"title"`
	Explanation          string         `json:"explanation,omitempty"`
	RemediationRef       string         `json:"remediation_ref,omitempty"`
	EvidenceRefs         []string       `json:"evidence_refs,omitempty"`
	Framework            []FrameworkRef `json:"framework,omitempty"`
	RequiresVerification bool           `json:"requires_verification"`
}

// MoscaResult is the Mosca inequality evaluated for one CRQC scenario: X (confidentiality
// lifetime) + Y (migration time) > Z (years until CRQC) means the data is exposed. HNDL
// flags harvest-now-decrypt-later: a Shor-broken confidentiality mechanism over data that
// outlives the CRQC arrival.
type MoscaResult struct {
	Scenario string  `json:"scenario"`
	X        float64 `json:"x_confidentiality_lifetime_years"`
	Y        float64 `json:"y_migration_time_years"`
	Z        float64 `json:"z_years_until_crqc"`
	Exposed  bool    `json:"exposed"`
	HNDL     bool    `json:"hndl"`
}

// Weights are the scoring weights echoed from the rule pack into the report appendix.
type Weights struct {
	QuantumVulnerability float64 `json:"quantum_vulnerability"`
	MoscaExposure        float64 `json:"mosca_exposure"`
	Criticality          float64 `json:"criticality"`
	EvidenceConfidence   float64 `json:"evidence_confidence"`
}

// RiskScore breaks a single asset's risk into its components plus the final weighted
// value in [0,1] (SPEC §6: never an opaque number without its breakdown). MoscaExposure is
// a sorted slice, not a map, so JSON output is deterministic.
type RiskScore struct {
	QuantumVulnerability float64       `json:"quantum_vulnerability"`
	MoscaExposure        []MoscaResult `json:"mosca_exposure,omitempty"`
	MoscaScore           float64       `json:"mosca_score"`
	Criticality          float64       `json:"criticality"`
	EvidenceConfidence   float64       `json:"evidence_confidence"`
	HNDL                 bool          `json:"hndl"`
	Final                float64       `json:"final"`
	Weights              Weights       `json:"weights"`

	// Notes records assumptions made when context was missing (e.g. "no linked system;
	// criticality defaulted to medium"), so the score stays honest and explainable.
	Notes []string `json:"notes,omitempty"`
}
