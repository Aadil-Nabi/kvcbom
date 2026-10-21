package cbom

import (
	"fmt"
	"sort"
	"strings"

	goyaml "github.com/goccy/go-yaml"

	"github.com/Aadil-Nabi/kvcbom/internal/safety"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// Mapping configures how vendor-specific CBOM extensions are read, so the ingester is not
// tied to any one scanner. Scanners differ in where they record the algorithm when the
// component name is something else (e.g. an endpoint): AlgorithmKeys lists the component
// property keys whose value is the algorithm name. A key is matched exactly or as a
// "*:suffix" wildcard — e.g. "*:algorithm" matches "qs:algorithm", "crypto:algorithm", etc.
// Adding support for a new tool's convention is a config change, not a code change.
type Mapping struct {
	AlgorithmKeys []string `yaml:"algorithm_keys"`
}

// DefaultMapping returns the built-in mapping, recognising the common conventions.
func DefaultMapping() *Mapping {
	return &Mapping{AlgorithmKeys: []string{"algorithm", "*:algorithm"}}
}

// withDefaults fills unset fields so a nil or partial mapping is always usable.
func (m *Mapping) withDefaults() *Mapping {
	if m == nil {
		return DefaultMapping()
	}
	if len(m.AlgorithmKeys) == 0 {
		m.AlgorithmKeys = DefaultMapping().AlgorithmKeys
	}
	return m
}

// LoadMapping reads a CBOM extension-mapping YAML file from disk.
func LoadMapping(path string) (*Mapping, error) {
	data, err := safety.ReadFileLimited(path, 1<<20)
	if err != nil {
		return nil, err
	}
	var m Mapping
	if err := goyaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse CBOM mapping %s: %w", path, err)
	}
	return m.withDefaults(), nil
}

// algorithmFromProperties returns the value of the first property whose key matches one of
// the mapping's AlgorithmKeys, or "" when none match. Properties are considered in sorted
// order so the result is deterministic.
func (m *Mapping) algorithmFromProperties(props []model.Property) string {
	for _, p := range props {
		v := strings.TrimSpace(p.Value)
		if v == "" {
			continue
		}
		for _, pat := range m.AlgorithmKeys {
			if keyMatches(pat, p.Key) {
				return v
			}
		}
	}
	return ""
}

// keyMatches reports whether a property key matches a mapping pattern: either an exact,
// case-insensitive match, or a "*:suffix" wildcard matching any key ending in ":suffix".
func keyMatches(pattern, key string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	key = strings.ToLower(strings.TrimSpace(key))
	if strings.HasPrefix(pattern, "*:") {
		return strings.HasSuffix(key, pattern[1:])
	}
	return key == pattern
}

// sortProperties orders properties by key then value for deterministic output.
func sortProperties(props []model.Property) {
	sort.Slice(props, func(i, j int) bool {
		if props[i].Key != props[j].Key {
			return props[i].Key < props[j].Key
		}
		return props[i].Value < props[j].Value
	})
}
