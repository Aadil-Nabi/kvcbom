package cbom

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

func td(name string) string { return filepath.Join("testdata", name) }

func mustIngest(t *testing.T, name string) *Result {
	t.Helper()
	res, err := IngestFile(td(name), Options{ValidateSchema: true})
	if err != nil {
		t.Fatalf("IngestFile(%s): unexpected error: %v", name, err)
	}
	return res
}

func assetByRef(b *model.Batch, ref string) *model.Asset {
	for i := range b.Assets {
		for _, e := range b.Assets[i].Evidence {
			if e.BOMRef == ref {
				return &b.Assets[i]
			}
		}
	}
	return nil
}

func TestIngestFile_Algorithm(t *testing.T) {
	res := mustIngest(t, "algorithm.cbom.json")
	if got := len(res.Batch.Assets); got != 2 {
		t.Fatalf("asset count = %d, want 2", got)
	}

	rsa := assetByRef(res.Batch, "alg:rsa-2048")
	if rsa == nil {
		t.Fatal("RSA asset not found")
	}
	if rsa.Type != model.AssetAlgorithm {
		t.Errorf("RSA type = %q, want algorithm", rsa.Type)
	}
	if rsa.Name != "RSA-2048" {
		t.Errorf("RSA name = %q, want RSA-2048", rsa.Name)
	}
	// CycloneDX 1.6 has no algorithmFamily field; the family is derived later during
	// classification, so it must be empty at ingest for a valid 1.6 input.
	if rsa.AlgorithmFamily != "" {
		t.Errorf("RSA family = %q, want empty (1.6 carries no family field)", rsa.AlgorithmFamily)
	}
	if rsa.Primitive != "pke" {
		t.Errorf("RSA primitive = %q, want pke", rsa.Primitive)
	}
	if rsa.ParameterSet != "2048" {
		t.Errorf("RSA parameter set = %q, want 2048", rsa.ParameterSet)
	}
	if rsa.OID != "1.2.840.113549.1.1.1" {
		t.Errorf("RSA OID = %q", rsa.OID)
	}
	if !reflect.DeepEqual(rsa.Functions, []string{"decrypt", "encrypt"}) {
		t.Errorf("RSA functions = %v, want sorted [decrypt encrypt]", rsa.Functions)
	}
	if !reflect.DeepEqual(rsa.Locations, []string{"src/payments/sign.go"}) {
		t.Errorf("RSA locations = %v", rsa.Locations)
	}
	if e := rsa.Evidence; len(e) != 1 || e[0].SourceType != model.SourceScannerCBOM || e[0].Confidence != model.C3 {
		t.Errorf("RSA evidence = %+v, want one scanner/C3 record", e)
	}

	kem := assetByRef(res.Batch, "alg:ml-kem-768")
	if kem == nil {
		t.Fatal("ML-KEM asset not found")
	}
	if kem.ParameterSet != "ML-KEM-768" {
		t.Errorf("ML-KEM parameter set = %q", kem.ParameterSet)
	}
}

func TestIngestFile_Certificate(t *testing.T) {
	res := mustIngest(t, "certificate.cbom.json")
	a := assetByRef(res.Batch, "cert:tls-leaf")
	if a == nil {
		t.Fatal("certificate asset not found")
	}
	if a.Type != model.AssetCertificate {
		t.Errorf("type = %q, want certificate", a.Type)
	}
	if a.Name == "" || a.OID == "" {
		t.Errorf("certificate name/oid should be populated: %+v", a)
	}
}

func TestIngestFile_Protocol(t *testing.T) {
	res := mustIngest(t, "protocol.cbom.json")
	a := assetByRef(res.Batch, "proto:tls-1.2")
	if a == nil {
		t.Fatal("protocol asset not found")
	}
	if a.Type != model.AssetProtocol {
		t.Errorf("type = %q, want protocol", a.Type)
	}
	if a.Name != "TLS 1.2" {
		t.Errorf("name = %q, want TLS 1.2", a.Name)
	}
	// The protocol version fills the (otherwise empty) parameter set.
	if a.ParameterSet != "1.2" {
		t.Errorf("parameter set = %q, want 1.2 (filled from protocol version)", a.ParameterSet)
	}
}

func TestIngestFile_Protocol_FillsNameFromType(t *testing.T) {
	// A nameless protocol component is not valid 1.6, so ingest it with schema
	// validation off to exercise the name-fallback branch directly.
	res, err := IngestFile(td("protocol-noname.cbom.json"), Options{ValidateSchema: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a := assetByRef(res.Batch, "proto:tls-noname")
	if a == nil {
		t.Fatal("protocol asset not found")
	}
	if a.Name != "tls" {
		t.Errorf("name = %q, want tls (filled from protocol type)", a.Name)
	}
}

func TestIngestFile_RelatedCryptoMaterial_KeySize(t *testing.T) {
	res := mustIngest(t, "related-crypto-material.cbom.json")
	a := assetByRef(res.Batch, "key:aes-256-data")
	if a == nil {
		t.Fatal("key material asset not found")
	}
	if a.Type != model.AssetRelatedCryptoMaterial {
		t.Errorf("type = %q, want related-crypto-material", a.Type)
	}
	if a.KeySizeBits == nil || *a.KeySizeBits != 256 {
		t.Errorf("key size = %v, want 256", a.KeySizeBits)
	}
}

func TestIngestFile_Mixed_NestedAndDependencies(t *testing.T) {
	res := mustIngest(t, "mixed.cbom.json")
	// Three crypto assets: two nested under the application, one top-level.
	if got := len(res.Batch.Assets); got != 3 {
		t.Fatalf("asset count = %d, want 3 (nested components must be collected)", got)
	}

	ecdsa := assetByRef(res.Batch, "alg:ecdsa-p256")
	if ecdsa == nil {
		t.Fatal("nested ECDSA asset not collected")
	}
	if ecdsa.Curve != "P-256" {
		t.Errorf("ECDSA curve = %q, want P-256", ecdsa.Curve)
	}

	if len(res.Batch.Dependencies) != 1 {
		t.Fatalf("dependency edges = %d, want 1", len(res.Batch.Dependencies))
	}
	edge := res.Batch.Dependencies[0]
	if edge.From != "proto:tls-1.3" {
		t.Errorf("edge.From = %q", edge.From)
	}
	want := []string{"alg:aes-256-gcm", "alg:ecdsa-p256"}
	if !reflect.DeepEqual(edge.To, want) {
		t.Errorf("edge.To = %v, want sorted %v", edge.To, want)
	}
}

func TestIngestFile_AssetsSortedByID(t *testing.T) {
	res := mustIngest(t, "mixed.cbom.json")
	for i := 1; i < len(res.Batch.Assets); i++ {
		if res.Batch.Assets[i-1].ID > res.Batch.Assets[i].ID {
			t.Fatalf("assets not sorted by ID at %d: %q > %q",
				i, res.Batch.Assets[i-1].ID, res.Batch.Assets[i].ID)
		}
	}
}

func TestIngestFile_Deterministic(t *testing.T) {
	a := mustIngest(t, "mixed.cbom.json")
	b := mustIngest(t, "mixed.cbom.json")
	if !reflect.DeepEqual(a.Batch, b.Batch) {
		t.Error("ingesting the same file twice produced different batches")
	}
	if a.Batch.SourceSHA256 == "" || a.Batch.SourceSHA256 != b.Batch.SourceSHA256 {
		t.Errorf("source SHA-256 not stable: %q vs %q", a.Batch.SourceSHA256, b.Batch.SourceSHA256)
	}
}

func TestIngestFile_XML(t *testing.T) {
	res := mustIngest(t, "algorithm.cbom.xml")
	if len(res.Batch.Assets) != 1 {
		t.Fatalf("asset count = %d, want 1", len(res.Batch.Assets))
	}
	a := res.Batch.Assets[0]
	if a.AlgorithmFamily != "RSA" || a.ParameterSet != "2048" {
		t.Errorf("XML-decoded asset = %+v, want RSA/2048", a)
	}
}

func TestIngestFile_Completeness(t *testing.T) {
	res := mustIngest(t, "incomplete.cbom.json")

	type key struct {
		ref   string
		field CompletenessField
	}
	got := map[key]CompletenessSeverity{}
	for _, is := range res.Completeness {
		// Map issue back to a ref via asset id.
		for _, a := range res.Batch.Assets {
			if a.ID == is.AssetID {
				got[key{a.Evidence[0].BOMRef, is.Field}] = is.Severity
			}
		}
	}

	wantWarnStrength := []string{"alg:mystery", "key:unsized"}
	for _, ref := range wantWarnStrength {
		if got[key{ref, FieldStrengthInfo}] != SeverityWarn {
			t.Errorf("%s: expected a strength_parameters warn, got %q", ref, got[key{ref, FieldStrengthInfo}])
		}
	}
	// Both assets lack an OID -> info.
	for _, ref := range wantWarnStrength {
		if got[key{ref, FieldOID}] != SeverityInfo {
			t.Errorf("%s: expected an oid info issue", ref)
		}
	}
	// Names are present, so identity must NOT be flagged.
	for _, is := range res.Completeness {
		if is.Field == FieldIdentity {
			t.Errorf("unexpected identity issue: %+v", is)
		}
	}
}

func TestIngestFile_CompletenessSorted(t *testing.T) {
	res := mustIngest(t, "incomplete.cbom.json")
	for i := 1; i < len(res.Completeness); i++ {
		p, c := res.Completeness[i-1], res.Completeness[i]
		if p.AssetID > c.AssetID || (p.AssetID == c.AssetID && p.Field > c.Field) {
			t.Fatalf("completeness issues not sorted at %d", i)
		}
	}
}

func TestIngestFile_SchemaInvalid(t *testing.T) {
	res, err := IngestFile(td("invalid-schema.json"), Options{ValidateSchema: true})
	if err != nil {
		t.Fatalf("unexpected hard error (file should decode): %v", err)
	}
	if res.SchemaError == nil {
		t.Fatal("expected a schema error for invalid-schema.json, got none")
	}
}

func TestIngestFile_SchemaValidationOptional(t *testing.T) {
	// With ValidateSchema off, no schema error is produced even for the bad file.
	res, err := IngestFile(td("invalid-schema.json"), Options{ValidateSchema: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.SchemaError != nil {
		t.Errorf("schema error should be nil when validation is disabled: %v", res.SchemaError)
	}
}

func TestIngestFile_UnknownFormat(t *testing.T) {
	_, err := IngestFile(td("not-cbom.txt"), Options{})
	if err == nil {
		t.Fatal("expected an unknown-format error")
	}
}

func TestIngestFile_MissingFile(t *testing.T) {
	_, err := IngestFile(td("does-not-exist.json"), Options{})
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestValidAssets_PassSchema(t *testing.T) {
	valid := []string{
		"algorithm.cbom.json",
		"certificate.cbom.json",
		"protocol.cbom.json",
		"related-crypto-material.cbom.json",
		"mixed.cbom.json",
		"incomplete.cbom.json",
	}
	for _, name := range valid {
		res := mustIngest(t, name)
		if res.SchemaError != nil {
			t.Errorf("%s: unexpected schema error: %v", name, res.SchemaError)
		}
	}
}
