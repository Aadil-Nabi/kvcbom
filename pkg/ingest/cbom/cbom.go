// Package cbom ingests CycloneDX 1.6 Cryptographic Bills of Materials and translates
// their crypto-asset components into kvcbom's normalised model. It is the only package
// that imports the CycloneDX types; everything downstream sees model.Asset.
package cbom

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/Aadil-Nabi/kvcbom/internal/hashid"
	"github.com/Aadil-Nabi/kvcbom/internal/safety"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// Options controls ingest behaviour.
type Options struct {
	// MaxInputBytes caps the size of an input file; 0 uses the safe default.
	MaxInputBytes int64
	// DefaultConfidence is the evidence confidence assigned to scanner-derived assets.
	DefaultConfidence model.ConfLevel
	// ValidateSchema runs JSON-Schema validation (JSON inputs only) before decoding.
	ValidateSchema bool
}

func (o Options) withDefaults() Options {
	if o.MaxInputBytes <= 0 {
		o.MaxInputBytes = safety.DefaultMaxInputBytes
	}
	if !o.DefaultConfidence.Valid() {
		o.DefaultConfidence = model.C2
	}
	return o
}

var (
	// ErrUnknownFormat is returned when an input is neither JSON nor XML.
	ErrUnknownFormat = errors.New("could not determine CBOM format (expected JSON or XML)")
	// ErrDecode wraps a CycloneDX decode failure.
	ErrDecode = errors.New("failed to decode CBOM")
)

// Result bundles the normalised batch and the completeness findings for one file.
// SchemaError is non-nil only when ValidateSchema was set and the input failed.
type Result struct {
	Batch        *model.Batch
	Completeness []CompletenessIssue
	SchemaError  error
}

// IngestFile reads, optionally schema-validates, decodes, and normalises one CBOM.
func IngestFile(path string, opts Options) (*Result, error) {
	opts = opts.withDefaults()

	data, err := safety.ReadFileLimited(path, opts.MaxInputBytes)
	if err != nil {
		return nil, err
	}
	format := safety.DetectFormat(path, data)
	if format == safety.FormatUnknown {
		return nil, fmt.Errorf("%s: %w", path, ErrUnknownFormat)
	}

	res := &Result{}
	if opts.ValidateSchema && format == safety.FormatJSON {
		res.SchemaError = ValidateSchema(data)
	}

	bom, err := decode(data, format)
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %v", path, ErrDecode, err)
	}

	res.Batch = normalise(bom, path, hashid.SHA256Hex(data), opts)
	res.Completeness = checkCompleteness(res.Batch)
	return res, nil
}

func decode(data []byte, format safety.Format) (*cdx.BOM, error) {
	var f cdx.BOMFileFormat
	switch format {
	case safety.FormatJSON:
		f = cdx.BOMFileFormatJSON
	case safety.FormatXML:
		f = cdx.BOMFileFormatXML
	default:
		return nil, ErrUnknownFormat
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), f).Decode(&bom); err != nil {
		return nil, err
	}
	return &bom, nil
}

// normalise walks the BOM's components (recursively) and builds a deterministic,
// sorted batch of crypto assets plus any dependency edges.
func normalise(bom *cdx.BOM, sourceFile, sha string, opts Options) *model.Batch {
	b := &model.Batch{SourceFile: sourceFile, SourceSHA256: sha}

	if bom.Components != nil {
		for i := range *bom.Components {
			collect(&(*bom.Components)[i], b, sourceFile, opts)
		}
	}

	if bom.Dependencies != nil {
		for _, d := range *bom.Dependencies {
			if strings.TrimSpace(d.Ref) == "" {
				continue
			}
			edge := model.DependencyEdge{From: d.Ref}
			if d.Dependencies != nil {
				edge.To = append(edge.To, (*d.Dependencies)...)
				sort.Strings(edge.To)
			}
			b.Dependencies = append(b.Dependencies, edge)
		}
		sort.Slice(b.Dependencies, func(i, j int) bool { return b.Dependencies[i].From < b.Dependencies[j].From })
	}

	sort.Slice(b.Assets, func(i, j int) bool {
		if b.Assets[i].ID != b.Assets[j].ID {
			return b.Assets[i].ID < b.Assets[j].ID
		}
		return b.Assets[i].Name < b.Assets[j].Name
	})
	return b
}

// collect appends the component to the batch if it is a crypto asset, then recurses
// into any nested components.
func collect(c *cdx.Component, b *model.Batch, sourceFile string, opts Options) {
	if c.Type == cdx.ComponentTypeCryptographicAsset && c.CryptoProperties != nil {
		b.Assets = append(b.Assets, buildAsset(c, sourceFile, opts))
	}
	if c.Components != nil {
		for i := range *c.Components {
			collect(&(*c.Components)[i], b, sourceFile, opts)
		}
	}
}

func buildAsset(c *cdx.Component, sourceFile string, opts Options) model.Asset {
	cp := c.CryptoProperties
	a := model.Asset{
		Type: mapAssetType(cp.AssetType),
		Name: strings.TrimSpace(c.Name),
		OID:  strings.TrimSpace(cp.OID),
	}

	if ap := cp.AlgorithmProperties; ap != nil {
		a.AlgorithmFamily = strings.TrimSpace(ap.AlgorithmFamily)
		a.ParameterSet = strings.TrimSpace(ap.ParameterSetIdentifier)
		a.Mode = strings.TrimSpace(string(ap.Mode))
		a.Primitive = strings.TrimSpace(string(ap.Primitive))
		a.Curve = firstNonEmpty(strings.TrimSpace(ap.EllipticCurve), strings.TrimSpace(ap.Curve))
		if ap.CryptoFunctions != nil {
			for _, fn := range *ap.CryptoFunctions {
				if s := strings.TrimSpace(string(fn)); s != "" {
					a.Functions = append(a.Functions, s)
				}
			}
			sort.Strings(a.Functions)
		}
	}

	if rp := cp.RelatedCryptoMaterialProperties; rp != nil {
		if rp.Size != nil {
			k := *rp.Size
			a.KeySizeBits = &k
		}
	}

	if pp := cp.ProtocolProperties; pp != nil {
		if a.Name == "" {
			a.Name = strings.TrimSpace(string(pp.Type))
		}
		if a.ParameterSet == "" {
			a.ParameterSet = strings.TrimSpace(pp.Version)
		}
	}

	a.Locations = occurrenceLocations(c)

	a.Evidence = []model.Evidence{{
		SourceType: model.SourceScannerCBOM,
		SourceFile: sourceFile,
		BOMRef:     c.BOMRef,
		Confidence: opts.DefaultConfidence,
	}}

	a.ID = model.AssetIdentity(a)
	return a
}

func mapAssetType(t cdx.CryptoAssetType) model.AssetType {
	switch t {
	case cdx.CryptoAssetTypeAlgorithm:
		return model.AssetAlgorithm
	case cdx.CryptoAssetTypeCertificate:
		return model.AssetCertificate
	case cdx.CryptoAssetTypeProtocol:
		return model.AssetProtocol
	case cdx.CryptoAssetTypeRelatedCryptoMaterial:
		return model.AssetRelatedCryptoMaterial
	default:
		return model.AssetUnknown
	}
}

func occurrenceLocations(c *cdx.Component) []string {
	if c.Evidence == nil || c.Evidence.Occurrences == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	for _, occ := range *c.Evidence.Occurrences {
		loc := strings.TrimSpace(occ.Location)
		if loc == "" {
			continue
		}
		if _, ok := seen[loc]; ok {
			continue
		}
		seen[loc] = struct{}{}
		out = append(out, loc)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
