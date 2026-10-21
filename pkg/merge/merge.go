// Package merge combines assets from multiple sources (several CBOMs and the manual
// register) into one deduplicated inventory. Assets with the same deterministic identity
// are collapsed into a single record whose evidence lists are merged rather than dropped,
// and every collapse is recorded in a decision log for the report appendix (SPEC §6).
package merge

import (
	"sort"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// InputHash records one source file and the SHA-256 of its bytes, for the report's
// traceability section.
type InputHash struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Decision records that two or more source records collapsed into one asset. It is emitted
// only when a merge actually happened (more than one contributing evidence record).
type Decision struct {
	AssetID   string   `json:"asset_id"`
	AssetName string   `json:"asset_name,omitempty"`
	Sources   []string `json:"sources"` // "file" or "file#bom-ref", sorted
}

// Result is the merged inventory plus provenance.
type Result struct {
	Assets      []model.Asset `json:"assets"`
	Decisions   []Decision    `json:"decisions"`
	InputHashes []InputHash   `json:"input_hashes"`
}

// Merge combines the batches. Output is deterministic: assets and their evidence are
// sorted, and set-valued fields (locations, functions, system/data-class links) are
// unioned and sorted.
func Merge(batches ...*model.Batch) *Result {
	groups := map[string][]model.Asset{}
	var order []string
	for _, b := range batches {
		if b == nil {
			continue
		}
		for _, a := range b.Assets {
			if _, seen := groups[a.ID]; !seen {
				order = append(order, a.ID)
			}
			groups[a.ID] = append(groups[a.ID], a)
		}
	}
	sort.Strings(order)

	res := &Result{}
	for _, id := range order {
		asset, dec := mergeGroup(groups[id])
		res.Assets = append(res.Assets, asset)
		if dec != nil {
			res.Decisions = append(res.Decisions, *dec)
		}
	}

	res.InputHashes = inputHashes(batches)
	return res
}

func mergeGroup(group []model.Asset) (model.Asset, *Decision) {
	// Deterministic base: the record with the most evidence, then lowest first-bom-ref.
	sort.SliceStable(group, func(i, j int) bool {
		if len(group[i].Evidence) != len(group[j].Evidence) {
			return len(group[i].Evidence) > len(group[j].Evidence)
		}
		return firstBOMRef(group[i]) < firstBOMRef(group[j])
	})

	out := group[0]
	out.Evidence = nil // rebuilt below
	locs := toSet(group[0].Locations)
	funcs := toSet(group[0].Functions)
	sys := toSet(group[0].SystemRefs)
	dc := toSet(group[0].DataClassRefs)
	var evidence []model.Evidence

	for _, a := range group {
		evidence = append(evidence, a.Evidence...)
		addAll(locs, a.Locations)
		addAll(funcs, a.Functions)
		addAll(sys, a.SystemRefs)
		addAll(dc, a.DataClassRefs)
		// Fill identity-independent fields from the first record that has them.
		out.Name = firstNonEmpty(out.Name, a.Name)
		out.AlgorithmFamily = firstNonEmpty(out.AlgorithmFamily, a.AlgorithmFamily)
		out.Implementation = firstNonEmpty(out.Implementation, a.Implementation)
		if out.KeySizeBits == nil && a.KeySizeBits != nil {
			k := *a.KeySizeBits
			out.KeySizeBits = &k
		}
	}

	out.Locations = sortedKeys(locs)
	out.Functions = sortedKeys(funcs)
	out.SystemRefs = sortedKeys(sys)
	out.DataClassRefs = sortedKeys(dc)
	out.Evidence = dedupEvidence(evidence)

	if len(out.Evidence) > 1 {
		return out, &Decision{AssetID: out.ID, AssetName: out.Name, Sources: evidenceSources(out.Evidence)}
	}
	return out, nil
}

func dedupEvidence(ev []model.Evidence) []model.Evidence {
	seen := map[model.Evidence]struct{}{}
	var out []model.Evidence
	for _, e := range ev {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceType != out[j].SourceType {
			return out[i].SourceType < out[j].SourceType
		}
		if out[i].SourceFile != out[j].SourceFile {
			return out[i].SourceFile < out[j].SourceFile
		}
		if out[i].BOMRef != out[j].BOMRef {
			return out[i].BOMRef < out[j].BOMRef
		}
		return out[i].Confidence < out[j].Confidence
	})
	return out
}

func evidenceSources(ev []model.Evidence) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, e := range ev {
		s := e.SourceFile
		if e.BOMRef != "" {
			s += "#" + e.BOMRef
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func inputHashes(batches []*model.Batch) []InputHash {
	seen := map[string]string{}
	for _, b := range batches {
		if b == nil || b.SourceFile == "" {
			continue
		}
		seen[b.SourceFile] = b.SourceSHA256
	}
	var out []InputHash
	for f, h := range seen {
		out = append(out, InputHash{File: f, SHA256: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].File < out[j].File })
	return out
}

func firstBOMRef(a model.Asset) string {
	if len(a.Evidence) > 0 {
		return a.Evidence[0].BOMRef
	}
	return ""
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func toSet(in []string) map[string]struct{} {
	m := make(map[string]struct{}, len(in))
	addAll(m, in)
	return m
}

func addAll(m map[string]struct{}, in []string) {
	for _, s := range in {
		if s != "" {
			m[s] = struct{}{}
		}
	}
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
