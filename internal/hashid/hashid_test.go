package hashid

import "testing"

func TestAssetID_StableAndLength(t *testing.T) {
	a := AssetID("algorithm", "RSA", "2048")
	b := AssetID("algorithm", "RSA", "2048")
	if a != b {
		t.Fatalf("AssetID not deterministic: %q != %q", a, b)
	}
	if len(a) != 16 {
		t.Fatalf("AssetID length = %d, want 16", len(a))
	}
}

func TestAssetID_FieldBoundaryMatters(t *testing.T) {
	// The unit separator must prevent "ab"+"c" colliding with "a"+"bc".
	if AssetID("ab", "c") == AssetID("a", "bc") {
		t.Fatal("AssetID collided across a field boundary")
	}
}

func TestAssetID_OrderMatters(t *testing.T) {
	if AssetID("a", "b") == AssetID("b", "a") {
		t.Fatal("AssetID should depend on field order")
	}
}

func TestSHA256Hex(t *testing.T) {
	// Known vector for the empty input.
	const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := SHA256Hex(nil); got != emptyHash {
		t.Fatalf("SHA256Hex(nil) = %q, want %q", got, emptyHash)
	}
}
