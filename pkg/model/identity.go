package model

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Aadil-Nabi/kvcbom/internal/hashid"
)

// AssetIdentity derives an asset's deterministic ID from its identity-bearing fields, in a
// fixed order, so the same asset collapses to one record when it appears in multiple CBOMs
// or in the manual register (SPEC §6 merging). Empty fields are kept so presence/absence is
// itself part of the identity; Name is folded in only when no stronger identifier exists,
// to avoid over-merging weakly described assets. Locations are sorted so ordering does not
// change the ID.
func AssetIdentity(a Asset) string {
	keySize := ""
	if a.KeySizeBits != nil {
		keySize = fmt.Sprintf("%d", *a.KeySizeBits)
	}
	locs := append([]string(nil), a.Locations...)
	sort.Strings(locs)
	parts := []string{
		string(a.Type), a.AlgorithmFamily, a.ParameterSet, a.Mode,
		a.Primitive, a.Curve, a.OID, keySize, a.Implementation,
		strings.Join(locs, ","),
	}
	if a.AlgorithmFamily == "" && a.ParameterSet == "" && a.OID == "" {
		parts = append(parts, a.Name)
	}
	return hashid.AssetID(parts...)
}
