// Package register ingests a manual asset register (XLSX or CSV) gathered from interviews
// or manual review, translating rows into the normalised model via a YAML column mapping
// so differently-laid-out spreadsheets are supported without code changes (SPEC §5.2).
package register

import (
	_ "embed"
	"fmt"

	goyaml "github.com/goccy/go-yaml"

	"github.com/Aadil-Nabi/kvcbom/internal/safety"
)

// Logical field names a mapping may bind to a column header.
const (
	fieldName           = "name"
	fieldType           = "type"
	fieldAlgoFamily     = "algorithm_family"
	fieldParameterSet   = "parameter_set"
	fieldKeySizeBits    = "key_size_bits"
	fieldMode           = "mode"
	fieldPrimitive      = "primitive"
	fieldCurve          = "curve"
	fieldOID            = "oid"
	fieldFunctions      = "functions"
	fieldImplementation = "implementation"
	fieldLocation       = "location"
	fieldSystemRefs     = "system_refs"
	fieldDataClassRefs  = "data_class_refs"
	fieldConfidence     = "confidence"
)

var knownFields = map[string]struct{}{
	fieldName: {}, fieldType: {}, fieldAlgoFamily: {}, fieldParameterSet: {},
	fieldKeySizeBits: {}, fieldMode: {}, fieldPrimitive: {}, fieldCurve: {},
	fieldOID: {}, fieldFunctions: {}, fieldImplementation: {}, fieldLocation: {},
	fieldSystemRefs: {}, fieldDataClassRefs: {}, fieldConfidence: {},
}

// Mapping binds logical asset fields to spreadsheet/CSV column headers.
type Mapping struct {
	HeaderRow     bool              `yaml:"header_row"`
	Sheet         string            `yaml:"sheet"`
	ListDelimiter string            `yaml:"list_delimiter"`
	Columns       map[string]string `yaml:"columns"`
}

//go:embed mapping-default.yaml
var defaultMappingYAML []byte

// DefaultMapping returns the built-in mapping (header names from mapping-default.yaml).
func DefaultMapping() *Mapping {
	m, err := parseMapping(defaultMappingYAML)
	if err != nil {
		// The embedded default is a test-covered constant; a parse failure is a build bug.
		panic(fmt.Sprintf("kvcbom: invalid embedded default register mapping: %v", err))
	}
	return m
}

// LoadMapping reads a mapping YAML file from disk.
func LoadMapping(path string) (*Mapping, error) {
	data, err := safety.ReadFileLimited(path, 1<<20)
	if err != nil {
		return nil, err
	}
	return parseMapping(data)
}

func parseMapping(data []byte) (*Mapping, error) {
	var m Mapping
	m.HeaderRow = true // default
	if err := goyaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse register mapping: %w", err)
	}
	if m.ListDelimiter == "" {
		m.ListDelimiter = ";"
	}
	if len(m.Columns) == 0 {
		return nil, fmt.Errorf("register mapping defines no columns")
	}
	for field := range m.Columns {
		if _, ok := knownFields[field]; !ok {
			return nil, fmt.Errorf("register mapping: unknown field %q", field)
		}
	}
	if !m.HeaderRow {
		return nil, fmt.Errorf("register mapping: header_row:false is not supported; the first row must be headers")
	}
	return &m, nil
}
