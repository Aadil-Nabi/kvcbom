// Package json renders a Report as the canonical JSON document. This is the source of
// truth from which every other format is produced and that `diff` consumes, so output is
// deterministic (struct field order is fixed; no maps are serialised) and HTML escaping is
// disabled to keep URLs and operators readable.
package json

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/Aadil-Nabi/kvcbom/pkg/report"
	"github.com/Aadil-Nabi/kvcbom/schemas"
)

// Renderer writes a Report as indented JSON.
type Renderer struct{}

// Render implements report.Renderer.
func (Renderer) Render(r *report.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Marshal returns the canonical JSON bytes for a report.
func Marshal(r *report.Report) ([]byte, error) {
	var buf bytes.Buffer
	if err := (Renderer{}).Render(r, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal parses canonical report JSON back into a Report. It rejects an unknown
// schema version so `diff` never silently compares incompatible documents.
func Unmarshal(data []byte) (*report.Report, error) {
	var r report.Report
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("parse report JSON: %w", err)
	}
	if r.SchemaVersion != report.SchemaVersion {
		return nil, fmt.Errorf("unsupported report schema_version %d (this build understands %d)",
			r.SchemaVersion, report.SchemaVersion)
	}
	return &r, nil
}

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	schemaErr  error
)

const schemaID = "https://kvcbom.dev/schema/report-1.schema.json"

func compileSchema() (*jsonschema.Schema, error) {
	schemaOnce.Do(func() {
		raw, err := schemas.FS.ReadFile("output/report-1.schema.json")
		if err != nil {
			schemaErr = fmt.Errorf("read embedded output schema: %w", err)
			return
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			schemaErr = fmt.Errorf("parse embedded output schema: %w", err)
			return
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(schemaID, doc); err != nil {
			schemaErr = fmt.Errorf("register output schema: %w", err)
			return
		}
		schema, schemaErr = c.Compile(schemaID)
	})
	return schema, schemaErr
}

// Validate checks canonical JSON bytes against the published output schema. It is used by
// tests and can be used by consumers to verify a report document.
func Validate(data []byte) error {
	sch, err := compileSchema()
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("report is not valid JSON: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return fmt.Errorf("report does not conform to the output schema: %w", err)
	}
	return nil
}
