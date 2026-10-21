package rulepack

import (
	"sort"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// Framework is the (optional) control framework a pack maps findings onto.
type Framework struct {
	ID       string
	Name     string
	Mappings []FrameworkMapping
}

// Pack is a loaded, parsed rule pack ready for use by the engine. Construct it only via
// Load or LoadPath, which parse and build the classifier. The zero value is not usable.
type Pack struct {
	meta        Meta
	classifier  *classify.Classifier
	entries     []classify.Entry // retained for `rulepacks show` and tests
	rules       []Rule
	remediation map[string]Remediation
	remedyOrder []string
	framework   Framework
	scoring     Scoring

	// hasTODO records whether any source-bearing field still carries a TODO(source)
	// marker, so reports can show the "unverified rule content" notice.
	hasTODO bool
}

// Meta returns the pack's identity and provenance.
func (p *Pack) Meta() Meta { return p.meta }

// Sources returns the pack's citations in declared order.
func (p *Pack) Sources() []Source { return p.meta.Sources }

// Classify maps an asset to its quantum status via the pack's classification table.
func (p *Pack) Classify(a model.Asset) (classify.Result, bool) {
	return p.classifier.Classify(a)
}

// Classifier exposes the underlying classifier (the engine builds findings from it).
func (p *Pack) Classifier() *classify.Classifier { return p.classifier }

// ClassificationEntries returns the parsed table entries, for display and tests.
func (p *Pack) ClassificationEntries() []classify.Entry { return p.entries }

// Rules returns the pack's rules in declared order.
func (p *Pack) Rules() []Rule { return p.rules }

// Remediation looks up guidance by its ID (a rule's Remediation reference).
func (p *Pack) Remediation(id string) (Remediation, bool) {
	r, ok := p.remediation[id]
	return r, ok
}

// RemediationIDs returns remediation IDs in declared order.
func (p *Pack) RemediationIDs() []string { return p.remedyOrder }

// Framework returns the control framework this pack maps to (zero value if none).
func (p *Pack) Framework() Framework { return p.framework }

// FrameworkMappings returns the finding-type → control mappings (empty for baseline).
func (p *Pack) FrameworkMappings() []FrameworkMapping { return p.framework.Mappings }

// Scoring returns the configurable weights echoed into the report appendix.
func (p *Pack) Scoring() Scoring { return p.scoring }

// HasUnverifiedContent reports whether the pack is draft/vendor status or still carries
// any TODO(source) marker — either of which makes a report flag its content as unverified.
func (p *Pack) HasUnverifiedContent() bool {
	return p.hasTODO || p.meta.Status == StatusDraft || p.meta.Status == StatusVendor
}

// sourceIDSet returns the set of declared source IDs, for reference validation.
func (p *Pack) sourceIDSet() map[string]struct{} {
	m := make(map[string]struct{}, len(p.meta.Sources))
	for _, s := range p.meta.Sources {
		m[s.ID] = struct{}{}
	}
	return m
}

// SeveritySorted returns the recognised severities most-severe first; used by callers
// that render findings grouped by severity.
func SeveritySorted(sevs []Severity) {
	rank := map[Severity]int{SevCritical: 0, SevHigh: 1, SevMedium: 2, SevLow: 3, SevInfo: 4}
	sort.SliceStable(sevs, func(i, j int) bool { return rank[sevs[i]] < rank[sevs[j]] })
}
