// Package rules evaluates a rule pack's declarative conditions against classified assets
// to produce findings. Each asset is classified via the pack's table, a RuleInput is built
// from the asset and its quantum status, and every rule whose `when` expression is true
// yields a finding carrying its rule id, severity, evidence, framework mapping, and a
// verification flag driven by evidence confidence. Output is deterministic.
package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/pkg/rulepack"
)

// AssetClassification pairs an asset with the classification result the pack produced for
// it, so the report's inventory can show each asset's quantum status with provenance.
type AssetClassification struct {
	AssetID string          `json:"asset_id"`
	Result  classify.Result `json:"result"`
	Matched bool            `json:"matched"`
}

// Result is the outcome of evaluating a pack against an asset inventory.
type Result struct {
	Findings        []model.Finding
	Classifications []AssetClassification
}

// Evaluate classifies each asset with the pack and runs the pack's rules against it. The
// pack should already have passed Validate; a rule whose expression fails to compile is a
// hard error here.
func Evaluate(assets []model.Asset, p *rulepack.Pack) (*Result, error) {
	type compiled struct {
		rule    rulepack.Rule
		program *vm.Program
	}
	var programs []compiled
	for _, r := range p.Rules() {
		prog, err := expr.Compile(r.When, expr.Env(rulepack.RuleInput{}), expr.AsBool())
		if err != nil {
			return nil, fmt.Errorf("rule %q: condition does not compile: %w", r.ID, err)
		}
		programs = append(programs, compiled{rule: r, program: prog})
	}

	// Pre-index framework mappings by finding type.
	fwByType := map[string][]model.FrameworkRef{}
	for _, m := range p.FrameworkMappings() {
		fwByType[m.FindingType] = append(fwByType[m.FindingType], model.FrameworkRef{
			ControlID:    m.ControlID,
			ControlTitle: m.ControlTitle,
			Source:       m.Source,
			Unverified:   strings.Contains(m.ControlID, rulepack.TODOMarker) || strings.Contains(m.ControlTitle, rulepack.TODOMarker),
		})
	}

	// Sort assets by ID for deterministic evaluation.
	sorted := append([]model.Asset(nil), assets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	res := &Result{}
	for _, a := range sorted {
		cres, ok := p.Classify(a)
		res.Classifications = append(res.Classifications, AssetClassification{AssetID: a.ID, Result: cres, Matched: ok})

		input := toInput(a, cres)
		requiresVerify := maxConfidence(a) <= model.C2

		for _, c := range programs {
			out, err := expr.Run(c.program, input)
			if err != nil {
				return nil, fmt.Errorf("rule %q: evaluation failed on asset %q: %w", c.rule.ID, a.ID, err)
			}
			hit, _ := out.(bool)
			if !hit {
				continue
			}
			f := model.Finding{
				RuleID:               c.rule.ID,
				FindingType:          c.rule.FindingType,
				Severity:             model.Severity(c.rule.Severity),
				AssetID:              a.ID,
				Title:                c.rule.Title,
				Explanation:          c.rule.Explanation,
				RemediationRef:       c.rule.Remediation,
				EvidenceRefs:         evidenceRefs(a),
				Framework:            fwByType[c.rule.FindingType],
				RequiresVerification: requiresVerify,
			}
			res.Findings = append(res.Findings, f)
		}
	}

	sort.SliceStable(res.Findings, func(i, j int) bool {
		fi, fj := res.Findings[i], res.Findings[j]
		if fi.Severity.Rank() != fj.Severity.Rank() {
			return fi.Severity.Rank() < fj.Severity.Rank()
		}
		if fi.AssetID != fj.AssetID {
			return fi.AssetID < fj.AssetID
		}
		return fi.RuleID < fj.RuleID
	})
	return res, nil
}

func toInput(a model.Asset, cres classify.Result) rulepack.RuleInput {
	in := rulepack.RuleInput{
		Type:         string(a.Type),
		Name:         a.Name,
		ParameterSet: a.ParameterSet,
		Mode:         a.Mode,
		Primitive:    a.Primitive,
		Curve:        a.Curve,
		OID:          a.OID,
		Functions:    a.Functions,
		Status:       string(cres.Status),
		MatchedEntry: cres.EntryID,
	}
	if a.KeySizeBits != nil {
		in.KeySizeBits = *a.KeySizeBits
		in.HasKeySize = true
	}
	if in.Functions == nil {
		in.Functions = []string{}
	}
	return in
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

func evidenceRefs(a model.Asset) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, e := range a.Evidence {
		s := e.SourceFile
		if e.BOMRef != "" {
			s += "#" + e.BOMRef
		}
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
