package cbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Aadil-Nabi/kvcbom/schemas"
)

// schemaResources maps each embedded schema file to the $id it declares. The bom schemas
// reference the SPDX and JSF schemas by relative path, which resolves against these ids.
var schemaResources = []struct{ file, id string }{
	{"cyclonedx/spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"},
	{"cyclonedx/jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json"},
	{"cyclonedx/cryptography-defs.schema.json", "http://cyclonedx.org/schema/cryptography-defs.schema.json"},
	{"cyclonedx/bom-1.6.schema.json", "http://cyclonedx.org/schema/bom-1.6.schema.json"},
	{"cyclonedx/bom-1.7.schema.json", "http://cyclonedx.org/schema/bom-1.7.schema.json"},
}

// bomSchemaIDs maps a CycloneDX specVersion to the $id of its bom schema. Adding a future
// version is a one-line change here plus embedding its schema file — no logic changes.
var bomSchemaIDs = map[string]string{
	"1.6": "http://cyclonedx.org/schema/bom-1.6.schema.json",
	"1.7": "http://cyclonedx.org/schema/bom-1.7.schema.json",
}

var (
	compiledOnce sync.Once
	compiled     map[string]*jsonschema.Schema // specVersion -> compiled schema
	compileErr   error
)

// compileSchemas compiles every supported CycloneDX bom schema once and caches them by
// specVersion. All resources are registered on one compiler so cross-schema references
// (SPDX, JSF) resolve.
func compileSchemas() (map[string]*jsonschema.Schema, error) {
	compiledOnce.Do(func() {
		c := jsonschema.NewCompiler()
		for _, r := range schemaResources {
			raw, err := schemas.FS.ReadFile(r.file)
			if err != nil {
				compileErr = fmt.Errorf("read embedded schema %s: %w", r.file, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				compileErr = fmt.Errorf("parse embedded schema %s: %w", r.file, err)
				return
			}
			if err := c.AddResource(r.id, doc); err != nil {
				compileErr = fmt.Errorf("register schema %s: %w", r.id, err)
				return
			}
		}
		out := make(map[string]*jsonschema.Schema, len(bomSchemaIDs))
		for version, id := range bomSchemaIDs {
			sch, err := c.Compile(id)
			if err != nil {
				compileErr = fmt.Errorf("compile CycloneDX %s schema: %w", version, err)
				return
			}
			out[version] = sch
		}
		compiled = out
	})
	return compiled, compileErr
}

// SupportedSpecVersions lists the CycloneDX versions kvcbom can schema-validate, sorted.
func SupportedSpecVersions() []string {
	out := make([]string, 0, len(bomSchemaIDs))
	for v := range bomSchemaIDs {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ValidateSchema checks raw CBOM JSON bytes against the CycloneDX JSON Schema matching the
// document's own specVersion (1.6 or 1.7). It returns a SchemaError describing the failures,
// or nil when valid. XML CBOMs are validated structurally via decoding; see Ingest.
func ValidateSchema(data []byte) error {
	set, err := compileSchemas()
	if err != nil {
		return err
	}

	version := detectSpecVersion(data)
	sch, ok := set[version]
	if !ok {
		return &SchemaError{
			Message: "unsupported CycloneDX specVersion",
			Detail:  fmt.Sprintf("%q (supported: %s)", version, strings.Join(SupportedSpecVersions(), ", ")),
		}
	}

	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return &SchemaError{Message: "input is not valid JSON", Detail: err.Error()}
	}
	if err := sch.Validate(inst); err != nil {
		return &SchemaError{
			Message: fmt.Sprintf("does not conform to CycloneDX %s schema", version),
			Detail:  err.Error(),
		}
	}
	return nil
}

// detectSpecVersion reads the specVersion field from a CycloneDX JSON document, defaulting
// to 1.6 when absent so legacy documents still validate against a concrete schema.
func detectSpecVersion(data []byte) string {
	var head struct {
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(data, &head); err == nil {
		if v := strings.TrimSpace(head.SpecVersion); v != "" {
			return v
		}
	}
	return "1.6"
}

// SchemaError is returned when an input fails JSON-Schema validation.
type SchemaError struct {
	Message string
	Detail  string
}

func (e *SchemaError) Error() string {
	if e.Detail == "" {
		return e.Message
	}
	return e.Message + ": " + e.Detail
}
