package model

// Criticality is a system's business criticality. It is an ordered, named scale so the
// context file stays readable; Weight maps it to [0,1] for scoring.
type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// Valid reports whether c is a recognised level.
func (c Criticality) Valid() bool {
	switch c {
	case CriticalityLow, CriticalityMedium, CriticalityHigh, CriticalityCritical:
		return true
	}
	return false
}

// Weight maps criticality to [0,1]. An unset/unknown level is treated as medium so an
// un-triaged system never silently scores as zero risk.
func (c Criticality) Weight() float64 {
	switch c {
	case CriticalityLow:
		return 0.25
	case CriticalityMedium:
		return 0.5
	case CriticalityHigh:
		return 0.75
	case CriticalityCritical:
		return 1.0
	default:
		return 0.5
	}
}

// System is a business system/application from the context file. It carries the data it
// handles (DataClassRefs), its criticality, and an optional migration-time override.
type System struct {
	ID                 string      `json:"id"`
	Name               string      `json:"name"`
	Owner              string      `json:"owner,omitempty"`
	Criticality        Criticality `json:"criticality"`
	CrownJewel         bool        `json:"crown_jewel"`
	DataClassRefs      []string    `json:"data_class_refs,omitempty"`
	MigrationTimeYears *float64    `json:"migration_time_years,omitempty"`
}

// DataClass is a class of data with a confidentiality lifetime — how many years it must
// stay secret. This is the X term in the Mosca inequality.
type DataClass struct {
	ID                           string  `json:"id"`
	Name                         string  `json:"name"`
	ConfidentialityLifetimeYears float64 `json:"confidentiality_lifetime_years"`
}

// CRQCScenario is one assumption about when a cryptographically relevant quantum computer
// arrives (the Z term). Scenarios are user-supplied (e.g. optimistic/central/pessimistic);
// kvcbom never hardcodes a single value as fact.
type CRQCScenario struct {
	Name       string  `json:"name"`
	YearsUntil float64 `json:"years_until"`
}

// LinkRule attaches matching CBOM components to a system. A component matches when its
// bom-ref is listed, its name matches a name pattern, or one of its locations matches a
// location pattern (useful for scanner CBOMs where assets are located at endpoints).
type LinkRule struct {
	SystemRef        string   `json:"system_ref"`
	BOMRefs          []string `json:"bom_refs,omitempty"`
	NamePatterns     []string `json:"name_patterns,omitempty"`
	LocationPatterns []string `json:"location_patterns,omitempty"`
}

// AssessmentMeta is the scope/attribution recorded on the report cover.
type AssessmentMeta struct {
	Organisation string `json:"organisation,omitempty"`
	Assessor     string `json:"assessor,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// Context is the business context a CBOM cannot carry (SPEC §5.3). It is optional; without
// it, assets are still classified but Mosca exposure and criticality cannot be computed.
type Context struct {
	Meta                     AssessmentMeta `json:"meta"`
	Systems                  []System       `json:"systems"`
	DataClasses              []DataClass    `json:"data_classes"`
	GlobalMigrationTimeYears float64        `json:"global_migration_time_years"`
	CRQCScenarios            []CRQCScenario `json:"crqc_scenarios"`
	LinkRules                []LinkRule     `json:"link_rules"`
}

// SystemByID returns the system with the given id, if present.
func (c *Context) SystemByID(id string) (System, bool) {
	for _, s := range c.Systems {
		if s.ID == id {
			return s, true
		}
	}
	return System{}, false
}

// DataClassByID returns the data class with the given id, if present.
func (c *Context) DataClassByID(id string) (DataClass, bool) {
	for _, d := range c.DataClasses {
		if d.ID == id {
			return d, true
		}
	}
	return DataClass{}, false
}
