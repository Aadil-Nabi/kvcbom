// Package classify maps a normalised cryptographic asset to a post-quantum
// status (Shor-broken, Grover-weakened, quantum-resistant, …) using a classification
// table supplied by a rule pack. It holds no standards content of its own: every entry,
// and the source behind it, comes from the pack. The matching is deterministic — the
// same asset and table always yield the same result — so reports are reproducible.
package classify

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// QuantumStatus is an algorithm's resistance to a cryptographically relevant quantum
// computer (CRQC). The values mirror the rule-pack vocabulary.
type QuantumStatus string

const (
	// StatusShorBroken: broken by Shor's algorithm on a CRQC (RSA, ECC, DH, DSA…).
	StatusShorBroken QuantumStatus = "shor_broken"
	// StatusGroverWeakened: security halved by Grover's algorithm; may need larger keys.
	StatusGroverWeakened QuantumStatus = "grover_weakened"
	// StatusQuantumResistant: no known practical quantum attack at the given parameters.
	StatusQuantumResistant QuantumStatus = "quantum_resistant"
	// StatusClassicallyBroken: already broken by classical cryptanalysis (MD5, SHA-1…).
	StatusClassicallyBroken QuantumStatus = "classically_broken"
	// StatusUnknown: no classification entry matched the asset.
	StatusUnknown QuantumStatus = "unknown"
)

// Valid reports whether s is a recognised status.
func (s QuantumStatus) Valid() bool {
	switch s {
	case StatusShorBroken, StatusGroverWeakened, StatusQuantumResistant,
		StatusClassicallyBroken, StatusUnknown:
		return true
	}
	return false
}

// Milestone is a dated lifecycle event (deprecation or disallowance) carried by a
// classification entry, each with its own source so the report can cite it.
type Milestone struct {
	Date     string `json:"date"` // free-form; a pack author fills the real date from the source
	SourceID string `json:"source_id"`
}

// KeyBits is an optional key-size constraint on a match. A nil bound is unconstrained;
// an asset with no recorded key size never satisfies a non-empty constraint.
type KeyBits struct {
	Eq  *int
	Min *int
	Max *int
}

func (k KeyBits) specified() bool { return k.Eq != nil || k.Min != nil || k.Max != nil }

func (k KeyBits) matches(bits *int) bool {
	if !k.specified() {
		return true
	}
	if bits == nil {
		return false
	}
	b := *bits
	if k.Eq != nil {
		return b == *k.Eq
	}
	if k.Min != nil && b < *k.Min {
		return false
	}
	if k.Max != nil && b > *k.Max {
		return false
	}
	return true
}

// Match is the set of conditions that select a classification entry. Every *specified*
// dimension must match (logical AND); an unspecified dimension is ignored. Name patterns
// are pre-compiled regexes; OIDs, parameter sets and curves are compared case-folded.
type Match struct {
	OIDs         []string
	ParamSets    []string
	NamePatterns []*regexp.Regexp
	Primitives   []string
	Curves       []string
	KeyBits      KeyBits
}

// Specificity weights. A more precise dimension outranks a looser one, so an OID match
// always beats a name-pattern match when both entries apply to the same asset.
const (
	wOID       = 1000
	wKeyBits   = 200
	wParamSet  = 100
	wCurve     = 80
	wName      = 10
	wPrimitive = 5
)

// Entry is one row of a pack's classification table.
type Entry struct {
	ID           string
	Status       QuantumStatus
	Rationale    string
	SourceID     string
	Primitive    string // the algorithm's role (e.g. key-agree, signature, pke); optional
	Deprecation  *Milestone
	Disallowance *Milestone
	Match        Match

	specificity int // precomputed from the specified dimensions
}

func (e *Entry) computeSpecificity() {
	s := 0
	if len(e.Match.OIDs) > 0 {
		s += wOID
	}
	if e.Match.KeyBits.specified() {
		s += wKeyBits
	}
	if len(e.Match.ParamSets) > 0 {
		s += wParamSet
	}
	if len(e.Match.Curves) > 0 {
		s += wCurve
	}
	if len(e.Match.NamePatterns) > 0 {
		s += wName
	}
	if len(e.Match.Primitives) > 0 {
		s += wPrimitive
	}
	e.specificity = s
}

// matchedDims returns, for an asset the entry matches, the dimensions that decided it.
// Used for report traceability ("matched RSA by oid, name").
func (e *Entry) match(a model.Asset) (bool, []string) {
	var dims []string

	if len(e.Match.OIDs) > 0 {
		if !containsFold(e.Match.OIDs, a.OID) {
			return false, nil
		}
		dims = append(dims, "oid")
	}
	if len(e.Match.ParamSets) > 0 {
		if !containsFold(e.Match.ParamSets, a.ParameterSet) {
			return false, nil
		}
		dims = append(dims, "param_set")
	}
	if len(e.Match.Curves) > 0 {
		if !containsFold(e.Match.Curves, a.Curve) {
			return false, nil
		}
		dims = append(dims, "curve")
	}
	if e.Match.KeyBits.specified() {
		if !e.Match.KeyBits.matches(a.KeySizeBits) {
			return false, nil
		}
		dims = append(dims, "key_bits")
	}
	if len(e.Match.NamePatterns) > 0 {
		// Match against the component name and the algorithm family. CycloneDX 1.6 carries no
		// family, but 1.7 populates algorithmProperties.algorithmFamily, so honouring both lets
		// the same name pattern classify richer 1.7 CBOMs that name the family rather than the
		// component.
		if !anyMatch(e.Match.NamePatterns, a.Name) && !anyMatch(e.Match.NamePatterns, a.AlgorithmFamily) {
			return false, nil
		}
		dims = append(dims, "name")
	}
	if len(e.Match.Primitives) > 0 {
		if !containsFold(e.Match.Primitives, a.Primitive) {
			return false, nil
		}
		dims = append(dims, "primitive")
	}

	// An entry with no criteria at all never matches: it would classify everything.
	if len(dims) == 0 {
		return false, nil
	}
	return true, dims
}

// Result is the outcome of classifying one asset. It records enough provenance for the
// report to explain and cite the classification.
type Result struct {
	Status       QuantumStatus `json:"status"`
	EntryID      string        `json:"entry_id,omitempty"`
	MatchedBy    []string      `json:"matched_by,omitempty"`
	SourceID     string        `json:"source_id,omitempty"`
	Primitive    string        `json:"primitive,omitempty"`
	Rationale    string        `json:"rationale,omitempty"`
	Deprecation  *Milestone    `json:"deprecation,omitempty"`
	Disallowance *Milestone    `json:"disallowance,omitempty"`
	PackID       string        `json:"pack_id"`
	PackVersion  string        `json:"pack_version"`
}

// Classifier applies a pack's classification table to assets.
type Classifier struct {
	packID      string
	packVersion string
	entries     []Entry
}

// New builds a Classifier from a pack's entries. The slice order is the pack's order and
// is used as the deterministic tie-breaker when two entries match with equal specificity.
func New(packID, packVersion string, entries []Entry) *Classifier {
	cp := make([]Entry, len(entries))
	copy(cp, entries)
	for i := range cp {
		cp[i].computeSpecificity()
	}
	return &Classifier{packID: packID, packVersion: packVersion, entries: cp}
}

// Classify returns the best-matching entry's result. ok is false (and Status is
// StatusUnknown) when nothing matched. When several entries match, the most specific
// wins; ties break to the earliest entry in pack order.
func (c *Classifier) Classify(a model.Asset) (Result, bool) {
	best := -1
	bestSpec := -1
	var bestDims []string
	for i := range c.entries {
		ok, dims := c.entries[i].match(a)
		if !ok {
			continue
		}
		if c.entries[i].specificity > bestSpec {
			best, bestSpec, bestDims = i, c.entries[i].specificity, dims
		}
	}
	if best < 0 {
		return Result{Status: StatusUnknown, PackID: c.packID, PackVersion: c.packVersion}, false
	}
	e := c.entries[best]
	sort.Strings(bestDims)
	return Result{
		Status:       e.Status,
		EntryID:      e.ID,
		MatchedBy:    bestDims,
		SourceID:     e.SourceID,
		Primitive:    e.Primitive,
		Rationale:    e.Rationale,
		Deprecation:  e.Deprecation,
		Disallowance: e.Disallowance,
		PackID:       c.packID,
		PackVersion:  c.packVersion,
	}, true
}

func containsFold(set []string, v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	for _, s := range set {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}

func anyMatch(res []*regexp.Regexp, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, re := range res {
		if re != nil && re.MatchString(name) {
			return true
		}
	}
	return false
}
