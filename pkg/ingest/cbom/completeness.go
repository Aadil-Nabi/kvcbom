package cbom

import (
	"sort"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// CompletenessField names a field whose absence weakens scoring.
type CompletenessField string

const (
	FieldIdentity     CompletenessField = "identity"
	FieldStrengthInfo CompletenessField = "strength_parameters"
	FieldOID          CompletenessField = "oid"
)

// CompletenessSeverity grades how much a missing field hurts the assessment.
type CompletenessSeverity string

const (
	SeverityWarn CompletenessSeverity = "warn" // scoring materially weakened
	SeverityInfo CompletenessSeverity = "info" // nice to have
)

// CompletenessIssue is a single gap found in an ingested asset. These are not
// findings about risk; they tell the assessor where the input data is thin.
type CompletenessIssue struct {
	AssetID   string               `json:"asset_id"`
	AssetName string               `json:"asset_name,omitempty"`
	Field     CompletenessField    `json:"field"`
	Severity  CompletenessSeverity `json:"severity"`
	Message   string               `json:"message"`
}

// checkCompleteness inspects each asset for fields that, if missing, limit scoring.
// Business-context links (systems, data classes) are supplied separately by a context
// file, so they are not flagged here.
func checkCompleteness(b *model.Batch) []CompletenessIssue {
	var issues []CompletenessIssue
	add := func(a model.Asset, f CompletenessField, sev CompletenessSeverity, msg string) {
		issues = append(issues, CompletenessIssue{
			AssetID: a.ID, AssetName: a.Name, Field: f, Severity: sev, Message: msg,
		})
	}

	for _, a := range b.Assets {
		if a.AlgorithmFamily == "" && a.Name == "" {
			add(a, FieldIdentity, SeverityWarn,
				"no algorithm family or name — the asset cannot be identified or classified")
		}

		switch a.Type {
		case model.AssetAlgorithm:
			if a.ParameterSet == "" && a.KeySizeBits == nil {
				add(a, FieldStrengthInfo, SeverityWarn,
					"no parameter set or key size — quantum strength cannot be judged")
			}
		case model.AssetRelatedCryptoMaterial:
			if a.KeySizeBits == nil {
				add(a, FieldStrengthInfo, SeverityWarn,
					"no key size recorded for key material")
			}
		}

		if a.OID == "" {
			add(a, FieldOID, SeverityInfo,
				"no OID — useful for unambiguous identification but not required")
		}
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].AssetID != issues[j].AssetID {
			return issues[i].AssetID < issues[j].AssetID
		}
		return issues[i].Field < issues[j].Field
	})
	return issues
}
