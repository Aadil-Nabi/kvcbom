// Package hashid produces the deterministic identifiers and content hashes used
// throughout kvcbom. Everything here is pure and side-effect free so that identical
// inputs always yield identical output.
package hashid

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// unitSep separates fields when hashing, so ("ab","c") and ("a","bc") differ.
const unitSep = "\x1f"

// AssetID returns a short, stable identifier derived from an asset's identity fields.
// Callers pass the identity-bearing fields in a fixed order; empty fields are kept so
// that presence/absence is itself part of the identity. The result is 16 hex chars
// (64 bits) — short enough to read in a report, wide enough to avoid collisions at the
// scale of a single assessment.
func AssetID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, unitSep)))
	return hex.EncodeToString(sum[:])[:16]
}

// SHA256Hex returns the full lowercase hex SHA-256 of b, used for recording input
// file hashes in the report for traceability.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
