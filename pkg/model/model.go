// Package model defines kvcbom's normalised internal representation of cryptographic
// assets and the evidence behind them. It is independent of any input format, so the
// rest of the engine never depends on a third-party schema type. Formats (CycloneDX,
// spreadsheet registers, context files) are translated into this model at ingest time.
package model

// AssetType is the kind of cryptographic asset, mirroring the CycloneDX crypto asset
// types plus an explicit unknown.
type AssetType string

const (
	AssetAlgorithm             AssetType = "algorithm"
	AssetCertificate           AssetType = "certificate"
	AssetProtocol              AssetType = "protocol"
	AssetRelatedCryptoMaterial AssetType = "related-crypto-material"
	AssetUnknown               AssetType = "unknown"
)

// SourceType records where a piece of evidence came from.
type SourceType string

const (
	SourceScannerCBOM    SourceType = "scanner-cbom"
	SourceManualRegister SourceType = "manual-register"
	SourceContext        SourceType = "context"
)

// ConfLevel is evidence confidence on a C1–C4 scale where C1 is weakest
// (asserted / verbal) and C4 is strongest (verified from live configuration).
type ConfLevel int

const (
	C1 ConfLevel = 1
	C2 ConfLevel = 2
	C3 ConfLevel = 3
	C4 ConfLevel = 4
)

// Valid reports whether the level is within C1–C4.
func (c ConfLevel) Valid() bool { return c >= C1 && c <= C4 }

func (c ConfLevel) String() string {
	switch c {
	case C1:
		return "C1"
	case C2:
		return "C2"
	case C3:
		return "C3"
	case C4:
		return "C4"
	default:
		return "C?"
	}
}

// Evidence is a single provenance record for an asset. An asset may carry several
// (e.g. the same algorithm seen in two CBOMs and asserted in the register).
type Evidence struct {
	SourceType SourceType `json:"source_type"`
	SourceFile string     `json:"source_file"`
	BOMRef     string     `json:"bom_ref,omitempty"`
	Confidence ConfLevel  `json:"confidence"`
}

// Asset is a normalised cryptographic asset. ID is deterministic: it is derived from
// the asset's identity fields so the same asset seen in multiple inputs collapses to
// one record during merge.
type Asset struct {
	ID              string    `json:"id"`
	Type            AssetType `json:"type"`
	Name            string    `json:"name,omitempty"`
	AlgorithmFamily string    `json:"algorithm_family,omitempty"`
	ParameterSet    string    `json:"parameter_set,omitempty"`
	KeySizeBits     *int      `json:"key_size_bits,omitempty"`
	Mode            string    `json:"mode,omitempty"`
	Primitive       string    `json:"primitive,omitempty"`
	Curve           string    `json:"curve,omitempty"`
	OID             string    `json:"oid,omitempty"`
	Functions       []string  `json:"functions,omitempty"`
	Implementation  string    `json:"implementation,omitempty"`
	Locations       []string  `json:"locations,omitempty"`

	// Links are populated by the context file (M3), not by a CBOM.
	SystemRefs    []string `json:"system_refs,omitempty"`
	DataClassRefs []string `json:"data_class_refs,omitempty"`

	Evidence []Evidence `json:"evidence"`
}

// DependencyEdge preserves a CBOM dependency relationship (e.g. protocol → cipher
// suite → algorithm, or certificate → signature algorithm).
type DependencyEdge struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}

// Batch is the result of ingesting one input source. SourceSHA256 is the hash of the
// raw input bytes, recorded for traceability in the report.
type Batch struct {
	SourceFile   string           `json:"source_file"`
	SourceSHA256 string           `json:"source_sha256"`
	Assets       []Asset          `json:"assets"`
	Dependencies []DependencyEdge `json:"dependencies,omitempty"`
}
