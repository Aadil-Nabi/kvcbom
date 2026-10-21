// Package schemas bundles the JSON Schema documents used for offline validation.
//
// The CycloneDX 1.6 schema and its referenced SPDX and JSF schemas are embedded so
// that `validate` works with no network access. Provenance for each file is recorded
// in cyclonedx/README.md.
package schemas

import "embed"

// FS holds the embedded JSON Schema documents.
//
//go:embed cyclonedx/*.json
//go:embed rulepack/*.json
//go:embed context/*.json
//go:embed output/*.json
var FS embed.FS
