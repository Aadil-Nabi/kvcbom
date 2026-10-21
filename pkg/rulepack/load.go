package rulepack

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"

	goyaml "github.com/goccy/go-yaml"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Aadil-Nabi/kvcbom/internal/hashid"
	"github.com/Aadil-Nabi/kvcbom/internal/safety"
	"github.com/Aadil-Nabi/kvcbom/pkg/classify"
	"github.com/Aadil-Nabi/kvcbom/rulepacks"
	"github.com/Aadil-Nabi/kvcbom/schemas"
)

// todoMarker flags unverified standards content. Its presence makes a report warn.
const todoMarker = "TODO(source):"

// TODOMarker is the exported form of the unverified-content marker, so other engine
// packages can detect placeholder control text without re-declaring the literal.
const TODOMarker = todoMarker

// DefaultMaxPackBytes caps the size of a pack file read from disk.
const DefaultMaxPackBytes int64 = 8 << 20 // 8 MiB

var (
	// ErrPackNotFound is returned when an id matches no embedded or on-disk pack.
	ErrPackNotFound = errors.New("rule pack not found")
	// ErrDirPack is returned for a directory path; multi-file packs are not yet supported.
	ErrDirPack = errors.New("directory rule packs are not yet supported; use a single YAML file")
)

// LoadedPack bundles a Pack with the SHA-256 of its source bytes, recorded in reports
// for traceability (SPEC §3.4).
type LoadedPack struct {
	Pack   *Pack
	SHA256 string
	Origin string // "embedded:<id>" or the file path
}

var (
	packSchemaOnce sync.Once
	packSchema     *jsonschema.Schema
	packSchemaErr  error
)

const packSchemaID = "https://kvcbom.dev/schema/rulepack-1.schema.json"

func compilePackSchema() (*jsonschema.Schema, error) {
	packSchemaOnce.Do(func() {
		raw, err := schemas.FS.ReadFile("rulepack/rulepack-1.schema.json")
		if err != nil {
			packSchemaErr = fmt.Errorf("read embedded rulepack schema: %w", err)
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			packSchemaErr = fmt.Errorf("parse embedded rulepack schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(packSchemaID, doc); err != nil {
			packSchemaErr = fmt.Errorf("register rulepack schema: %w", err)
			return
		}
		packSchema, packSchemaErr = c.Compile(packSchemaID)
	})
	return packSchema, packSchemaErr
}

// Load resolves idOrPath to a pack: if it names an existing file it is loaded from disk,
// otherwise it is treated as an embedded pack id.
func Load(idOrPath string) (*LoadedPack, error) {
	if fi, err := os.Stat(idOrPath); err == nil {
		if fi.IsDir() {
			return nil, fmt.Errorf("%s: %w", idOrPath, ErrDirPack)
		}
		return LoadPath(idOrPath)
	}
	return LoadEmbedded(idOrPath)
}

// LoadEmbedded loads one of the packs shipped inside the binary.
func LoadEmbedded(id string) (*LoadedPack, error) {
	data, ok := rulepacks.Read(id)
	if !ok {
		return nil, fmt.Errorf("%q: %w (available: %s)", id, ErrPackNotFound,
			strings.Join(rulepacks.Names(), ", "))
	}
	p, err := loadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("embedded pack %q: %w", id, err)
	}
	return &LoadedPack{Pack: p, SHA256: hashid.SHA256Hex(data), Origin: "embedded:" + id}, nil
}

// LoadPath loads a single-file pack from disk.
func LoadPath(path string) (*LoadedPack, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%s: %w", path, ErrDirPack)
	}
	data, err := safety.ReadFileLimited(path, DefaultMaxPackBytes)
	if err != nil {
		return nil, err
	}
	p, err := loadBytes(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &LoadedPack{Pack: p, SHA256: hashid.SHA256Hex(data), Origin: path}, nil
}

// List returns the metadata of every embedded pack, sorted by id.
func List() ([]Meta, error) {
	var out []Meta
	for _, id := range rulepacks.Names() {
		lp, err := LoadEmbedded(id)
		if err != nil {
			return nil, err
		}
		out = append(out, lp.Pack.Meta())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// loadBytes parses, schema-validates, and builds a Pack from YAML bytes. It fails on
// anything that prevents constructing a usable pack (bad YAML, schema violation, bad
// regex). Semantic issues such as missing source references are reported by Validate.
func loadBytes(data []byte) (*Pack, error) {
	if err := validateSchema(data); err != nil {
		return nil, err
	}

	var r raw
	if err := goyaml.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse pack YAML: %w", err)
	}

	p, err := build(&r)
	if err != nil {
		return nil, err
	}
	p.hasTODO = bytes.Contains(data, []byte(todoMarker))
	return p, nil
}

func validateSchema(data []byte) error {
	sch, err := compilePackSchema()
	if err != nil {
		return err
	}
	var v any
	if err := goyaml.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("pack is not valid YAML: %w", err)
	}
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("normalise pack to JSON: %w", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(jsonBytes))
	if err != nil {
		return fmt.Errorf("decode pack: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("pack does not conform to the rule-pack schema: %w", err)
	}
	return nil
}

// build converts the raw YAML shape into the domain Pack, compiling regexes.
func build(r *raw) (*Pack, error) {
	p := &Pack{
		meta: Meta{
			ID:          r.ID,
			Version:     r.Version,
			Name:        r.Name,
			Description: r.Description,
			Status:      Status(r.Status),
		},
		remediation: map[string]Remediation{},
	}

	for _, s := range r.Sources {
		p.meta.Sources = append(p.meta.Sources, Source{
			ID: s.ID, Title: s.Title, URL: s.URL,
			Status: Status(s.Status), RetrievedDate: s.RetrievedDate,
		})
	}

	entries := make([]classify.Entry, 0, len(r.Classifications))
	for _, c := range r.Classifications {
		m, err := buildMatch(c.Match)
		if err != nil {
			return nil, fmt.Errorf("classification %q: %w", c.ID, err)
		}
		entries = append(entries, classify.Entry{
			ID:           c.ID,
			Status:       classify.QuantumStatus(c.QuantumStatus),
			Rationale:    c.Rationale,
			SourceID:     c.Source,
			Deprecation:  milestone(c.Deprecation),
			Disallowance: milestone(c.Disallowance),
			Match:        m,
		})
	}
	p.entries = entries
	p.classifier = classify.New(r.ID, r.Version, entries)

	for _, rl := range r.Rules {
		p.rules = append(p.rules, Rule{
			ID: rl.ID, Title: rl.Title, Severity: Severity(rl.Severity),
			FindingType: rl.FindingType, When: rl.When,
			Explanation: rl.Explanation, Remediation: rl.Remediation,
		})
	}

	for _, rm := range r.Remediation {
		p.remediation[rm.ID] = Remediation{
			ID: rm.ID, Summary: rm.Summary, Detail: rm.Detail, References: rm.References,
		}
		p.remedyOrder = append(p.remedyOrder, rm.ID)
	}

	if r.Framework != nil {
		p.framework = Framework{ID: r.Framework.ID, Name: r.Framework.Name}
		for _, mp := range r.Framework.Mappings {
			p.framework.Mappings = append(p.framework.Mappings, FrameworkMapping{
				FindingType: mp.FindingType, ControlID: mp.ControlID,
				ControlTitle: mp.ControlTitle, Source: mp.Source,
			})
		}
	}

	p.scoring = Scoring{Weights: r.Scoring.Weights, SeverityScores: r.Scoring.SeverityScores}
	return p, nil
}

func buildMatch(m rawMatch) (classify.Match, error) {
	out := classify.Match{
		OIDs:       trimAll(m.OIDs),
		ParamSets:  trimAll(m.ParamSets),
		Primitives: trimAll(m.Primitives),
		Curves:     trimAll(m.Curves),
	}
	for _, pat := range m.NamePatterns {
		re, err := regexp.Compile(pat)
		if err != nil {
			return classify.Match{}, fmt.Errorf("invalid name pattern %q: %w", pat, err)
		}
		out.NamePatterns = append(out.NamePatterns, re)
	}
	if m.KeyBits != nil {
		out.KeyBits = classify.KeyBits{Eq: m.KeyBits.Eq, Min: m.KeyBits.Min, Max: m.KeyBits.Max}
	}
	return out, nil
}

func milestone(m *rawMilestone) *classify.Milestone {
	if m == nil {
		return nil
	}
	return &classify.Milestone{Date: m.Date, SourceID: m.Source}
}

func trimAll(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}
