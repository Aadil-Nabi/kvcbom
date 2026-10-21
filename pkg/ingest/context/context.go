// Package context ingests the optional assessment context file (SPEC §5.3): business
// systems, data classes with confidentiality lifetimes, migration-time assumptions, CRQC
// scenarios, and rules linking CBOM components to systems. It validates the file against
// an embedded JSON Schema and links assets to their systems and data classes so the
// scorer can compute Mosca exposure.
package context

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	goyaml "github.com/goccy/go-yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Aadil-Nabi/kvcbom/internal/hashid"
	"github.com/Aadil-Nabi/kvcbom/internal/safety"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/schemas"
)

// DefaultMaxContextBytes caps the size of a context file read from disk.
const DefaultMaxContextBytes int64 = 8 << 20 // 8 MiB

// Result bundles the parsed context with the SHA-256 of its source bytes (for the report
// input-hash list) and any completeness issues.
type Result struct {
	Context      *model.Context
	SHA256       string
	Completeness []Issue
}

type rawContext struct {
	SchemaVersion            int            `yaml:"schema_version"`
	Meta                     rawMeta        `yaml:"meta"`
	GlobalMigrationTimeYears float64        `yaml:"global_migration_time_years"`
	CRQCScenarios            []rawScenario  `yaml:"crqc_scenarios"`
	Systems                  []rawSystem    `yaml:"systems"`
	DataClasses              []rawDataClass `yaml:"data_classes"`
	LinkRules                []rawLinkRule  `yaml:"link_rules"`
}

type rawMeta struct {
	Organisation string `yaml:"organisation"`
	Assessor     string `yaml:"assessor"`
	Scope        string `yaml:"scope"`
}

type rawScenario struct {
	Name       string  `yaml:"name"`
	YearsUntil float64 `yaml:"years_until"`
}

type rawSystem struct {
	ID                 string   `yaml:"id"`
	Name               string   `yaml:"name"`
	Owner              string   `yaml:"owner"`
	Criticality        string   `yaml:"criticality"`
	CrownJewel         bool     `yaml:"crown_jewel"`
	DataClassRefs      []string `yaml:"data_class_refs"`
	MigrationTimeYears *float64 `yaml:"migration_time_years"`
}

type rawDataClass struct {
	ID                           string  `yaml:"id"`
	Name                         string  `yaml:"name"`
	ConfidentialityLifetimeYears float64 `yaml:"confidentiality_lifetime_years"`
}

type rawLinkRule struct {
	SystemRef        string   `yaml:"system_ref"`
	BOMRefs          []string `yaml:"bom_refs"`
	NamePatterns     []string `yaml:"name_patterns"`
	LocationPatterns []string `yaml:"location_patterns"`
}

// LoadFile reads, schema-validates, and parses a context file.
func LoadFile(path string) (*Result, error) {
	data, err := safety.ReadFileLimited(path, DefaultMaxContextBytes)
	if err != nil {
		return nil, err
	}
	ctx, err := parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Result{
		Context:      ctx,
		SHA256:       hashid.SHA256Hex(data),
		Completeness: checkCompleteness(ctx),
	}, nil
}

func parse(data []byte) (*model.Context, error) {
	if err := validateSchema(data); err != nil {
		return nil, err
	}
	var r rawContext
	if err := goyaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse context YAML: %w", err)
	}
	return build(&r), nil
}

func build(r *rawContext) *model.Context {
	c := &model.Context{
		Meta: model.AssessmentMeta{
			Organisation: r.Meta.Organisation, Assessor: r.Meta.Assessor, Scope: r.Meta.Scope,
		},
		GlobalMigrationTimeYears: r.GlobalMigrationTimeYears,
	}
	for _, s := range r.CRQCScenarios {
		c.CRQCScenarios = append(c.CRQCScenarios, model.CRQCScenario{Name: s.Name, YearsUntil: s.YearsUntil})
	}
	for _, s := range r.Systems {
		c.Systems = append(c.Systems, model.System{
			ID: s.ID, Name: s.Name, Owner: s.Owner,
			Criticality: model.Criticality(s.Criticality), CrownJewel: s.CrownJewel,
			DataClassRefs: s.DataClassRefs, MigrationTimeYears: s.MigrationTimeYears,
		})
	}
	for _, d := range r.DataClasses {
		c.DataClasses = append(c.DataClasses, model.DataClass{
			ID: d.ID, Name: d.Name, ConfidentialityLifetimeYears: d.ConfidentialityLifetimeYears,
		})
	}
	for _, l := range r.LinkRules {
		c.LinkRules = append(c.LinkRules, model.LinkRule{
			SystemRef: l.SystemRef, BOMRefs: l.BOMRefs,
			NamePatterns: l.NamePatterns, LocationPatterns: l.LocationPatterns,
		})
	}
	return c
}

var (
	ctxSchemaOnce sync.Once
	ctxSchema     *jsonschema.Schema
	ctxSchemaErr  error
)

const ctxSchemaID = "https://kvcbom.dev/schema/context-1.schema.json"

func compileSchema() (*jsonschema.Schema, error) {
	ctxSchemaOnce.Do(func() {
		raw, err := schemas.FS.ReadFile("context/context-1.schema.json")
		if err != nil {
			ctxSchemaErr = fmt.Errorf("read embedded context schema: %w", err)
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			ctxSchemaErr = fmt.Errorf("parse embedded context schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(ctxSchemaID, doc); err != nil {
			ctxSchemaErr = fmt.Errorf("register context schema: %w", err)
			return
		}
		ctxSchema, ctxSchemaErr = c.Compile(ctxSchemaID)
	})
	return ctxSchema, ctxSchemaErr
}

func validateSchema(data []byte) error {
	sch, err := compileSchema()
	if err != nil {
		return err
	}
	var v any
	if err := goyaml.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("context is not valid YAML: %w", err)
	}
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("normalise context to JSON: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("decode context: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("context does not conform to the context schema: %w", err)
	}
	return nil
}

// Link attaches systems and their data classes to assets by applying the context's link
// rules. It returns a new slice (inputs are not mutated); each asset's SystemRefs and
// DataClassRefs are sorted and de-duplicated for deterministic output. Assets matching no
// rule are returned unchanged.
func Link(assets []model.Asset, ctx *model.Context) ([]model.Asset, error) {
	if ctx == nil {
		return assets, nil
	}
	// Pre-compile name patterns per rule.
	type compiledRule struct {
		systemRef   string
		bomRefs     map[string]struct{}
		patterns    []*regexp.Regexp
		locPatterns []*regexp.Regexp
	}
	rules := make([]compiledRule, 0, len(ctx.LinkRules))
	for i, lr := range ctx.LinkRules {
		cr := compiledRule{systemRef: lr.SystemRef, bomRefs: map[string]struct{}{}}
		for _, b := range lr.BOMRefs {
			cr.bomRefs[b] = struct{}{}
		}
		for _, p := range lr.NamePatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("link rule #%d: invalid name pattern %q: %w", i+1, p, err)
			}
			cr.patterns = append(cr.patterns, re)
		}
		for _, p := range lr.LocationPatterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("link rule #%d: invalid location pattern %q: %w", i+1, p, err)
			}
			cr.locPatterns = append(cr.locPatterns, re)
		}
		rules = append(rules, cr)
	}

	out := make([]model.Asset, len(assets))
	copy(out, assets)
	for i := range out {
		a := &out[i]
		sysSet := toSet(a.SystemRefs)
		dcSet := toSet(a.DataClassRefs)
		for _, cr := range rules {
			if !ruleMatches(cr.bomRefs, cr.patterns, cr.locPatterns, a) {
				continue
			}
			sys, ok := ctx.SystemByID(cr.systemRef)
			if !ok {
				continue // dangling system ref is reported by completeness, not here
			}
			sysSet[sys.ID] = struct{}{}
			for _, dc := range sys.DataClassRefs {
				dcSet[dc] = struct{}{}
			}
		}
		a.SystemRefs = sortedKeys(sysSet)
		a.DataClassRefs = sortedKeys(dcSet)
	}
	return out, nil
}

func ruleMatches(bomRefs map[string]struct{}, patterns, locPatterns []*regexp.Regexp, a *model.Asset) bool {
	for _, ev := range a.Evidence {
		if _, ok := bomRefs[ev.BOMRef]; ok && ev.BOMRef != "" {
			return true
		}
	}
	name := strings.TrimSpace(a.Name)
	if name != "" {
		for _, re := range patterns {
			if re.MatchString(name) {
				return true
			}
		}
	}
	for _, loc := range a.Locations {
		for _, re := range locPatterns {
			if re.MatchString(loc) {
				return true
			}
		}
	}
	return false
}

func toSet(in []string) map[string]struct{} {
	m := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s != "" {
			m[s] = struct{}{}
		}
	}
	return m
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
