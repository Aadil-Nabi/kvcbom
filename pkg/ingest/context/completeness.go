package context

import (
	"fmt"
	"sort"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// Level grades a context completeness issue.
type Level string

const (
	LevelWarn Level = "warn" // scoring will be materially limited
	LevelInfo Level = "info" // worth noting
)

// Issue is a gap in the context that limits scoring. These are not schema errors (the
// file is well-formed); they tell the assessor what is missing for a full assessment.
type Issue struct {
	Level    Level  `json:"level"`
	Location string `json:"location"`
	Message  string `json:"message"`
}

func (i Issue) String() string { return fmt.Sprintf("[%s] %s: %s", i.Level, i.Location, i.Message) }

// checkCompleteness reports context gaps that limit Mosca/criticality scoring. Dangling
// references (a system's data class, or a link rule's system) are flagged here rather than
// failing the load, so an assessor can iterate on a partial context.
func checkCompleteness(c *model.Context) []Issue {
	var issues []Issue
	add := func(l Level, loc, msg string) { issues = append(issues, Issue{Level: l, Location: loc, Message: msg}) }

	if len(c.Systems) == 0 {
		add(LevelWarn, "systems", "no systems defined — criticality cannot be assessed")
	}
	if len(c.DataClasses) == 0 {
		add(LevelWarn, "data_classes", "no data classes defined — Mosca confidentiality lifetime (X) cannot be computed")
	}
	if len(c.LinkRules) == 0 {
		add(LevelWarn, "link_rules", "no link rules — CBOM assets will not be linked to any system")
	}
	if c.GlobalMigrationTimeYears == 0 {
		add(LevelInfo, "global_migration_time_years", "global migration time is 0; set it or per-system overrides for a meaningful Mosca (Y) term")
	}

	dcIDs := map[string]struct{}{}
	for _, d := range c.DataClasses {
		dcIDs[d.ID] = struct{}{}
		if d.ConfidentialityLifetimeYears == 0 {
			add(LevelInfo, fmt.Sprintf("data_class %q", d.ID), "confidentiality lifetime is 0 years")
		}
	}

	sysIDs := map[string]struct{}{}
	for _, s := range c.Systems {
		sysIDs[s.ID] = struct{}{}
		if !s.Criticality.Valid() {
			add(LevelWarn, fmt.Sprintf("system %q", s.ID), fmt.Sprintf("criticality %q is not a recognised level", s.Criticality))
		}
		for _, ref := range s.DataClassRefs {
			if _, ok := dcIDs[ref]; !ok {
				add(LevelWarn, fmt.Sprintf("system %q", s.ID), fmt.Sprintf("references undefined data class %q", ref))
			}
		}
	}

	for i, l := range c.LinkRules {
		if _, ok := sysIDs[l.SystemRef]; !ok {
			add(LevelWarn, fmt.Sprintf("link_rule #%d", i+1), fmt.Sprintf("references undefined system %q", l.SystemRef))
		}
		if len(l.BOMRefs) == 0 && len(l.NamePatterns) == 0 {
			add(LevelInfo, fmt.Sprintf("link_rule #%d", i+1), "has no bom_refs or name_patterns and will match nothing")
		}
	}

	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Location != issues[j].Location {
			return issues[i].Location < issues[j].Location
		}
		return issues[i].Message < issues[j].Message
	})
	return issues
}
