// Package rulepack loads, validates, and exposes versioned rule packs. A pack supplies
// the standards content kvcbom itself must never invent: the algorithm classification
// table, the rules that turn classifications into findings, framework-control mappings,
// remediation guidance, and the scoring weights. Packs are embedded for air-gapped use
// and overridable from disk. This package is the only one that parses pack YAML.
package rulepack

// Status is a pack's or source's maturity. A pack built from draft or vendor material
// causes reports to carry an "unverified rule content" notice.
type Status string

const (
	StatusFinal  Status = "final"
	StatusDraft  Status = "draft"
	StatusVendor Status = "vendor"
)

// Severity is a finding's severity, highest to lowest.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// raw is the on-disk YAML shape of a pack. It is deliberately permissive so that
// validation (not unmarshalling) produces the user-facing error list.
type raw struct {
	SchemaVersion   int           `yaml:"schema_version"`
	ID              string        `yaml:"id"`
	Version         string        `yaml:"version"`
	Name            string        `yaml:"name"`
	Description     string        `yaml:"description"`
	Status          string        `yaml:"status"`
	Sources         []rawSource   `yaml:"sources"`
	Classifications []rawClass    `yaml:"classifications"`
	Rules           []rawRule     `yaml:"rules"`
	Remediation     []rawRemedy   `yaml:"remediation"`
	Framework       *rawFramework `yaml:"framework"`
	Scoring         rawScoring    `yaml:"scoring"`
}

type rawSource struct {
	ID            string `yaml:"id"`
	Title         string `yaml:"title"`
	URL           string `yaml:"url"`
	Status        string `yaml:"status"`
	RetrievedDate string `yaml:"retrieved_date"`
}

type rawMilestone struct {
	Date   string `yaml:"date"`
	Source string `yaml:"source"`
}

type rawMatch struct {
	OIDs         []string    `yaml:"oids"`
	ParamSets    []string    `yaml:"param_sets"`
	NamePatterns []string    `yaml:"name_patterns"`
	Primitives   []string    `yaml:"primitives"`
	Curves       []string    `yaml:"curves"`
	KeyBits      *rawKeyBits `yaml:"key_bits"`
}

type rawKeyBits struct {
	Eq  *int `yaml:"eq"`
	Min *int `yaml:"min"`
	Max *int `yaml:"max"`
}

type rawClass struct {
	ID            string        `yaml:"id"`
	QuantumStatus string        `yaml:"quantum_status"`
	Rationale     string        `yaml:"rationale"`
	Source        string        `yaml:"source"`
	Deprecation   *rawMilestone `yaml:"deprecation"`
	Disallowance  *rawMilestone `yaml:"disallowance"`
	Match         rawMatch      `yaml:"match"`
}

type rawRule struct {
	ID          string `yaml:"id"`
	Title       string `yaml:"title"`
	Severity    string `yaml:"severity"`
	FindingType string `yaml:"finding_type"`
	When        string `yaml:"when"`
	Explanation string `yaml:"explanation"`
	Remediation string `yaml:"remediation"`
}

type rawRemedy struct {
	ID         string   `yaml:"id"`
	Summary    string   `yaml:"summary"`
	Detail     string   `yaml:"detail"`
	References []string `yaml:"references"`
}

type rawFramework struct {
	ID       string          `yaml:"id"`
	Name     string          `yaml:"name"`
	Mappings []rawFwkMapping `yaml:"mappings"`
}

type rawFwkMapping struct {
	FindingType  string `yaml:"finding_type"`
	ControlID    string `yaml:"control_id"`
	ControlTitle string `yaml:"control_title"`
	Source       string `yaml:"source"`
}

type rawScoring struct {
	Weights        map[string]float64 `yaml:"weights"`
	SeverityScores map[string]float64 `yaml:"severity_scores"`
}

// --- Domain types exposed to the rest of the engine ---

// Meta is a pack's identity and provenance.
type Meta struct {
	ID          string
	Version     string
	Name        string
	Description string
	Status      Status
	Sources     []Source
}

// Source is a citation. Every classification and rule references one by ID.
type Source struct {
	ID            string
	Title         string
	URL           string
	Status        Status
	RetrievedDate string
}

// Rule is a declarative condition over an asset (and its classification) that produces a
// finding. The condition is compiled from the pack's `when` expression.
type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	FindingType string
	When        string
	Explanation string
	Remediation string
}

// Remediation is guidance keyed by finding type via a rule's Remediation reference.
type Remediation struct {
	ID         string
	Summary    string
	Detail     string
	References []string
}

// FrameworkMapping links a finding type to a framework control. For packs that only
// classify (e.g. baseline-pqc) the mapping list is empty.
type FrameworkMapping struct {
	FindingType  string
	ControlID    string
	ControlTitle string
	Source       string
}

// Scoring holds the configurable weights echoed into the report appendix (SPEC §8).
type Scoring struct {
	Weights        map[string]float64
	SeverityScores map[string]float64
}

// RuleInput is the environment a rule's `when` expression evaluates against. It is the
// stable contract between pack authors and the engine; the rule evaluator (M3) builds
// one per asset, and pack validation compiles each expression against this type.
type RuleInput struct {
	Type         string   `expr:"Type"`
	Name         string   `expr:"Name"`
	ParameterSet string   `expr:"ParameterSet"`
	KeySizeBits  int      `expr:"KeySizeBits"`
	HasKeySize   bool     `expr:"HasKeySize"`
	Mode         string   `expr:"Mode"`
	Primitive    string   `expr:"Primitive"`
	Curve        string   `expr:"Curve"`
	OID          string   `expr:"OID"`
	Functions    []string `expr:"Functions"`
	Status       string   `expr:"Status"`
	MatchedEntry string   `expr:"MatchedEntry"`
}
