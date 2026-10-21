package cbom

import (
	"path/filepath"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

func TestDetectSpecVersion(t *testing.T) {
	cases := map[string]string{
		`{"specVersion":"1.7"}`:     "1.7",
		`{"specVersion":"1.6"}`:     "1.6",
		`{"bomFormat":"CycloneDX"}`: "1.6", // default when absent
		`{"specVersion":"  1.7  "}`: "1.7", // trimmed
	}
	for in, want := range cases {
		if got := detectSpecVersion([]byte(in)); got != want {
			t.Errorf("detectSpecVersion(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestSupportedSpecVersions(t *testing.T) {
	got := SupportedSpecVersions()
	if len(got) != 2 || got[0] != "1.6" || got[1] != "1.7" {
		t.Errorf("SupportedSpecVersions() = %v, want [1.6 1.7]", got)
	}
}

func TestValidateSchema_VersionSelect(t *testing.T) {
	// A 1.6 doc with a 1.7-only field (ellipticCurve) must fail under 1.6.
	v16with17 := `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
		{"type":"cryptographic-asset","bom-ref":"a","name":"x","cryptoProperties":{"assetType":"algorithm",
		"algorithmProperties":{"ellipticCurve":"nist/P-256"}}}]}`
	if err := ValidateSchema([]byte(v16with17)); err == nil {
		t.Error("expected 1.6 validation to reject the 1.7-only ellipticCurve field")
	}

	// An unknown specVersion is reported clearly, not silently accepted.
	if err := ValidateSchema([]byte(`{"bomFormat":"CycloneDX","specVersion":"9.9","version":1}`)); err == nil {
		t.Error("expected an error for an unsupported specVersion")
	}
}

func TestIngest_CycloneDX17_ValidatesAndClassifiesByFamily(t *testing.T) {
	res, err := IngestFile(filepath.Join("testdata", "algorithm-1.7.cbom.json"),
		Options{ValidateSchema: true})
	if err != nil {
		t.Fatalf("IngestFile: %v", err)
	}
	if res.SchemaError != nil {
		t.Fatalf("1.7 CBOM should validate against the 1.7 schema, got: %v", res.SchemaError)
	}
	if len(res.Batch.Assets) != 1 {
		t.Fatalf("asset count = %d, want 1", len(res.Batch.Assets))
	}
	a := res.Batch.Assets[0]
	// The component name does not contain "ECDSA"; the family field carries it.
	if a.AlgorithmFamily != "ECDSA" {
		t.Errorf("algorithm family = %q, want ECDSA", a.AlgorithmFamily)
	}
	if a.Curve != "nist/P-256" {
		t.Errorf("curve = %q, want nist/P-256 (1.7 ellipticCurve)", a.Curve)
	}
}

func TestIngest_VendorPropertyMapping(t *testing.T) {
	path := filepath.Join("testdata", "vendor-props.cbom.json")

	// Default mapping does not know "acme:cipher", so the name stays the endpoint.
	def, err := IngestFile(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := def.Batch.Assets[0].Name; got != "10.0.0.5:443" {
		t.Errorf("default mapping: name = %q, want the endpoint", got)
	}

	// A custom mapping that reads "*:cipher" adopts the algorithm as the identity and demotes
	// the endpoint to a location.
	m, err := LoadMapping(filepath.Join("testdata", "mapping-cipher.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cust, err := IngestFile(path, Options{Mapping: m})
	if err != nil {
		t.Fatal(err)
	}
	a := cust.Batch.Assets[0]
	if a.Name != "RSA-2048" {
		t.Errorf("custom mapping: name = %q, want RSA-2048", a.Name)
	}
	found := false
	for _, loc := range a.Locations {
		if loc == "10.0.0.5:443" {
			found = true
		}
	}
	if !found {
		t.Errorf("endpoint should be demoted to a location, locations = %v", a.Locations)
	}
}

func TestMapping_KeyMatching(t *testing.T) {
	cases := []struct {
		pattern, key string
		want         bool
	}{
		{"algorithm", "algorithm", true},
		{"algorithm", "Algorithm", true},
		{"algorithm", "qs:algorithm", false},
		{"*:algorithm", "qs:algorithm", true},
		{"*:algorithm", "crypto:algorithm", true},
		{"*:algorithm", "algorithm", false},
		{"*:cipher", "acme:cipher", true},
	}
	for _, c := range cases {
		if got := keyMatches(c.pattern, c.key); got != c.want {
			t.Errorf("keyMatches(%q,%q) = %v, want %v", c.pattern, c.key, got, c.want)
		}
	}
}

func TestMapping_Defaults(t *testing.T) {
	var m *Mapping
	d := m.withDefaults()
	if len(d.AlgorithmKeys) == 0 {
		t.Fatal("nil mapping should get default keys")
	}
	// Default recognises the common conventions.
	if d.algorithmFromProperties([]model.Property{{Key: "qs:algorithm", Value: "RSA"}}) != "RSA" {
		t.Error("default mapping should read *:algorithm")
	}
}
