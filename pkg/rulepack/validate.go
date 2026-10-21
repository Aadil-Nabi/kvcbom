package rulepack

import (
	"fmt"
	"sort"
	"strings"

	"github.com/expr-lang/expr"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
)

// IssueLevel grades a validation issue.
type IssueLevel string

const (
	// LevelError marks a pack unfit for use (e.g. a missing source reference).
	LevelError IssueLevel = "error"
	// LevelWarn marks content that should be reviewed (e.g. a TODO(source) marker).
	LevelWarn IssueLevel = "warn"
)

// PackIssue is one problem found by Validate.
type PackIssue struct {
	Level    IssueLevel `json:"level"`
	Location string     `json:"location"` // where the issue is, e.g. `classification "rsa"`
	Message  string     `json:"message"`
}

func (i PackIssue) String() string {
	return fmt.Sprintf("[%s] %s: %s", i.Level, i.Location, i.Message)
}

// Validate runs the pack's semantic checks (SPEC §7). A classification, milestone,
// framework mapping, or remediation reference that names no declared source is an
// error; a remaining TODO(source) marker, or a classification that can never match, is
// a warning. The schema (checked at load time) guarantees structural shape, so Validate
// focuses on cross-references, rule compilation, and unverified content.
func (p *Pack) Validate() []PackIssue {
	var issues []PackIssue
	add := func(level IssueLevel, loc, msg string) {
		issues = append(issues, PackIssue{Level: level, Location: loc, Message: msg})
	}

	sources := p.sourceIDSet()

	// Duplicate and TODO-bearing sources.
	seenSrc := map[string]bool{}
	for _, s := range p.meta.Sources {
		loc := fmt.Sprintf("source %q", s.ID)
		if seenSrc[s.ID] {
			add(LevelError, loc, "duplicate source id")
		}
		seenSrc[s.ID] = true
		if hasTODO(s.URL) || hasTODO(s.Title) {
			add(LevelWarn, loc, "source still carries a TODO(source) marker — fill and verify it")
		}
	}

	// Classifications: source must resolve; milestones must resolve; warn on empty match.
	seenClass := map[string]bool{}
	for _, e := range p.entries {
		loc := fmt.Sprintf("classification %q", e.ID)
		if seenClass[e.ID] {
			add(LevelError, loc, "duplicate classification id")
		}
		seenClass[e.ID] = true

		if strings.TrimSpace(e.SourceID) == "" {
			add(LevelError, loc, "missing source reference")
		} else if _, ok := sources[e.SourceID]; !ok {
			add(LevelError, loc, fmt.Sprintf("source %q is not declared in sources", e.SourceID))
		}
		checkMilestone(add, loc+" deprecation", e.Deprecation, sources)
		checkMilestone(add, loc+" disallowance", e.Disallowance, sources)

		if matchIsEmpty(e.Match) {
			add(LevelWarn, loc, "no match criteria — this entry will never classify any asset")
		}
		if hasTODO(e.Rationale) {
			add(LevelWarn, loc, "rationale carries a TODO(source) marker")
		}
	}

	// Remediation: ids unique, references resolve.
	seenRem := map[string]bool{}
	for _, id := range p.remedyOrder {
		r := p.remediation[id]
		loc := fmt.Sprintf("remediation %q", id)
		if seenRem[id] {
			add(LevelError, loc, "duplicate remediation id")
		}
		seenRem[id] = true
		for _, ref := range r.References {
			if _, ok := sources[ref]; !ok {
				add(LevelError, loc, fmt.Sprintf("reference %q is not a declared source", ref))
			}
		}
	}

	// Rules: ids unique, remediation reference resolves, `when` compiles.
	seenRule := map[string]bool{}
	for _, rl := range p.rules {
		loc := fmt.Sprintf("rule %q", rl.ID)
		if seenRule[rl.ID] {
			add(LevelError, loc, "duplicate rule id")
		}
		seenRule[rl.ID] = true

		if rl.Remediation != "" {
			if _, ok := p.remediation[rl.Remediation]; !ok {
				add(LevelError, loc, fmt.Sprintf("remediation %q is not defined", rl.Remediation))
			}
		}
		if _, err := expr.Compile(rl.When, expr.Env(RuleInput{}), expr.AsBool()); err != nil {
			add(LevelError, loc, fmt.Sprintf("condition does not compile: %v", err))
		}
	}

	// Framework mappings: source must resolve; TODO content warns.
	for i, m := range p.framework.Mappings {
		loc := fmt.Sprintf("framework mapping #%d (%s)", i+1, m.FindingType)
		if strings.TrimSpace(m.Source) == "" {
			add(LevelError, loc, "missing source reference")
		} else if _, ok := sources[m.Source]; !ok {
			add(LevelError, loc, fmt.Sprintf("source %q is not declared", m.Source))
		}
		if hasTODO(m.ControlID) || hasTODO(m.ControlTitle) {
			add(LevelWarn, loc, "control identifier/title is an unfilled TODO(source) placeholder")
		}
	}

	sortIssues(issues)
	return issues
}

// ValidationError summarises a pack's errors for callers that must refuse to use it.
func ValidationError(issues []PackIssue) error {
	var errs []string
	for _, i := range issues {
		if i.Level == LevelError {
			errs = append(errs, i.String())
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("rule pack has %d error(s):\n  %s", len(errs), strings.Join(errs, "\n  "))
}

func checkMilestone(add func(IssueLevel, string, string), loc string, m *classify.Milestone, sources map[string]struct{}) {
	if m == nil {
		return
	}
	if strings.TrimSpace(m.SourceID) == "" {
		add(LevelError, loc, "missing source reference")
	} else if _, ok := sources[m.SourceID]; !ok {
		add(LevelError, loc, fmt.Sprintf("source %q is not declared", m.SourceID))
	}
	if hasTODO(m.Date) {
		add(LevelWarn, loc, "date is an unfilled TODO(source) placeholder")
	}
}

func matchIsEmpty(m classify.Match) bool {
	noKeyBits := m.KeyBits.Eq == nil && m.KeyBits.Min == nil && m.KeyBits.Max == nil
	return len(m.OIDs) == 0 && len(m.ParamSets) == 0 && len(m.NamePatterns) == 0 &&
		len(m.Primitives) == 0 && len(m.Curves) == 0 && noKeyBits
}

func hasTODO(s string) bool { return strings.Contains(s, todoMarker) }

func sortIssues(issues []PackIssue) {
	rank := map[IssueLevel]int{LevelError: 0, LevelWarn: 1}
	sort.SliceStable(issues, func(i, j int) bool {
		if rank[issues[i].Level] != rank[issues[j].Level] {
			return rank[issues[i].Level] < rank[issues[j].Level]
		}
		if issues[i].Location != issues[j].Location {
			return issues[i].Location < issues[j].Location
		}
		return issues[i].Message < issues[j].Message
	})
}
