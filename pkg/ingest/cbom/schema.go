package cbom

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Aadil-Nabi/kvcbom/schemas"
)

// schemaResources maps each embedded schema file to the $id it declares. The bom
// schema references the other two by relative path, which resolves against these ids.
var schemaResources = []struct{ file, id string }{
	{"cyclonedx/spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"},
	{"cyclonedx/jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json"},
	{"cyclonedx/bom-1.6.schema.json", "http://cyclonedx.org/schema/bom-1.6.schema.json"},
}

const bomSchemaID = "http://cyclonedx.org/schema/bom-1.6.schema.json"

var (
	compiledOnce sync.Once
	compiled     *jsonschema.Schema
	compileErr   error
)

// cyclonedxSchema compiles the embedded CycloneDX 1.6 schema once and caches it.
func cyclonedxSchema() (*jsonschema.Schema, error) {
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
		compiled, compileErr = c.Compile(bomSchemaID)
	})
	return compiled, compileErr
}

// ValidateSchema checks raw CBOM JSON bytes against the CycloneDX 1.6 JSON Schema.
// It returns a SchemaError describing the failures, or nil when valid. XML CBOMs are
// validated structurally via decoding (CycloneDX publishes no XSD in this tool's
// bundle); see Ingest.
func ValidateSchema(data []byte) error {
	sch, err := cyclonedxSchema()
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return &SchemaError{Message: "input is not valid JSON", Detail: err.Error()}
	}
	if err := sch.Validate(inst); err != nil {
		return &SchemaError{Message: "does not conform to CycloneDX 1.6 schema", Detail: err.Error()}
	}
	return nil
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
