package classify

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

func ptr(i int) *int { return &i }

func nameEntry(id string, status QuantumStatus, pat string) Entry {
	return Entry{ID: id, Status: status, SourceID: "s", Match: Match{NamePatterns: []*regexp.Regexp{regexp.MustCompile(pat)}}}
}

func TestClassify_NoMatchIsUnknown(t *testing.T) {
	c := New("p", "1.0.0", []Entry{nameEntry("rsa", StatusShorBroken, "(?i)rsa")})
	res, ok := c.Classify(model.Asset{Name: "Blowfish"})
	if ok {
		t.Fatalf("expected no match, got %+v", res)
	}
	if res.Status != StatusUnknown {
		t.Errorf("status = %q, want unknown", res.Status)
	}
}

func TestClassify_OIDBeatsName(t *testing.T) {
	entries := []Entry{
		nameEntry("rsa-name", StatusGroverWeakened, "(?i)rsa"), // wrong status, weaker match
		{ID: "rsa-oid", Status: StatusShorBroken, SourceID: "s", Match: Match{OIDs: []string{"1.2.840.113549.1.1.1"}}},
	}
	c := New("p", "1.0.0", entries)
	res, ok := c.Classify(model.Asset{Name: "RSA-2048", OID: "1.2.840.113549.1.1.1"})
	if !ok {
		t.Fatal("expected a match")
	}
	if res.EntryID != "rsa-oid" || res.Status != StatusShorBroken {
		t.Errorf("OID should win: got entry %q status %q", res.EntryID, res.Status)
	}
	if !reflect.DeepEqual(res.MatchedBy, []string{"oid"}) {
		t.Errorf("MatchedBy = %v, want [oid]", res.MatchedBy)
	}
}

func TestClassify_TieBreaksToPackOrder(t *testing.T) {
	entries := []Entry{
		nameEntry("first", StatusQuantumResistant, "(?i)aes"),
		nameEntry("second", StatusGroverWeakened, "(?i)aes"),
	}
	c := New("p", "1.0.0", entries)
	res, _ := c.Classify(model.Asset{Name: "AES-GCM"})
	if res.EntryID != "first" {
		t.Errorf("tie should break to earliest entry, got %q", res.EntryID)
	}
}

func TestClassify_KeyBits(t *testing.T) {
	entries := []Entry{
		{ID: "aes-weak", Status: StatusGroverWeakened, SourceID: "s", Match: Match{
			NamePatterns: []*regexp.Regexp{regexp.MustCompile("(?i)aes")}, KeyBits: KeyBits{Eq: ptr(128)}}},
		{ID: "aes-strong", Status: StatusQuantumResistant, SourceID: "s", Match: Match{
			NamePatterns: []*regexp.Regexp{regexp.MustCompile("(?i)aes")}, KeyBits: KeyBits{Min: ptr(256)}}},
		nameEntry("aes-generic", StatusGroverWeakened, "(?i)aes"),
	}
	c := New("p", "1.0.0", entries)

	// 128-bit: key_bits entry (specificity name+key_bits) beats the generic name-only entry.
	res, _ := c.Classify(model.Asset{Name: "AES", KeySizeBits: ptr(128)})
	if res.EntryID != "aes-weak" {
		t.Errorf("128-bit AES: got %q, want aes-weak", res.EntryID)
	}
	// 256-bit: quantum-resistant.
	res, _ = c.Classify(model.Asset{Name: "AES", KeySizeBits: ptr(256)})
	if res.EntryID != "aes-strong" || res.Status != StatusQuantumResistant {
		t.Errorf("256-bit AES: got %q/%q, want aes-strong/quantum_resistant", res.EntryID, res.Status)
	}
	// No key size: key_bits entries cannot match, falls back to the generic entry.
	res, _ = c.Classify(model.Asset{Name: "AES"})
	if res.EntryID != "aes-generic" {
		t.Errorf("sizeless AES: got %q, want aes-generic", res.EntryID)
	}
}

func TestClassify_EmptyMatchNeverApplies(t *testing.T) {
	c := New("p", "1.0.0", []Entry{{ID: "catch-all", Status: StatusShorBroken, SourceID: "s"}})
	if _, ok := c.Classify(model.Asset{Name: "anything"}); ok {
		t.Fatal("an entry with no criteria must never match")
	}
}

func TestClassify_Deterministic(t *testing.T) {
	c := New("p", "1.0.0", []Entry{
		{ID: "e", Status: StatusShorBroken, SourceID: "s", Match: Match{
			OIDs:         []string{"1.1"},
			NamePatterns: []*regexp.Regexp{regexp.MustCompile("(?i)rsa")},
		}},
	})
	a := model.Asset{Name: "RSA", OID: "1.1"}
	r1, _ := c.Classify(a)
	r2, _ := c.Classify(a)
	if !reflect.DeepEqual(r1, r2) {
		t.Error("classification is not deterministic")
	}
	// Both dimensions matched, reported sorted.
	if !reflect.DeepEqual(r1.MatchedBy, []string{"name", "oid"}) {
		t.Errorf("MatchedBy = %v, want sorted [name oid]", r1.MatchedBy)
	}
}

func TestClassify_AllDimensions(t *testing.T) {
	entries := []Entry{
		{ID: "by-param", Status: StatusShorBroken, SourceID: "s", Match: Match{ParamSets: []string{"2048"}}},
		{ID: "by-curve", Status: StatusShorBroken, SourceID: "s", Match: Match{Curves: []string{"P-256"}}},
		{ID: "by-primitive", Status: StatusQuantumResistant, SourceID: "s", Match: Match{Primitives: []string{"kem"}}},
	}
	c := New("p", "1.0.0", entries)

	if r, ok := c.Classify(model.Asset{ParameterSet: "2048"}); !ok || r.EntryID != "by-param" {
		t.Errorf("param_set match failed: %+v ok=%v", r, ok)
	}
	// Curve match is case-insensitive.
	if r, ok := c.Classify(model.Asset{Curve: "p-256"}); !ok || r.EntryID != "by-curve" {
		t.Errorf("curve match failed: %+v ok=%v", r, ok)
	}
	if r, ok := c.Classify(model.Asset{Primitive: "kem"}); !ok || r.EntryID != "by-primitive" {
		t.Errorf("primitive match failed: %+v ok=%v", r, ok)
	}
}

func TestClassify_ResultCarriesRationaleAndMilestones(t *testing.T) {
	dep := &Milestone{Date: "2030-01-01", SourceID: "s"}
	c := New("p", "1.0.0", []Entry{{
		ID: "rsa", Status: StatusShorBroken, SourceID: "s", Rationale: "because Shor",
		Deprecation: dep, Match: Match{NamePatterns: []*regexp.Regexp{regexp.MustCompile("(?i)rsa")}},
	}})
	r, _ := c.Classify(model.Asset{Name: "RSA"})
	if r.Rationale != "because Shor" || r.Deprecation == nil || r.Deprecation.Date != "2030-01-01" {
		t.Errorf("result did not carry rationale/milestone: %+v", r)
	}
}

func TestQuantumStatus_Valid(t *testing.T) {
	valid := []QuantumStatus{StatusShorBroken, StatusGroverWeakened, StatusQuantumResistant, StatusClassicallyBroken, StatusUnknown}
	for _, s := range valid {
		if !s.Valid() {
			t.Errorf("%q should be valid", s)
		}
	}
	if QuantumStatus("nonsense").Valid() {
		t.Error("an unrecognised status must be invalid")
	}
}

func TestKeyBits_Matches(t *testing.T) {
	cases := []struct {
		kb   KeyBits
		bits *int
		want bool
	}{
		{KeyBits{}, nil, true},              // no constraint
		{KeyBits{Eq: ptr(128)}, nil, false}, // constraint but no size
		{KeyBits{Eq: ptr(128)}, ptr(128), true},
		{KeyBits{Eq: ptr(128)}, ptr(256), false},
		{KeyBits{Min: ptr(256)}, ptr(256), true},
		{KeyBits{Min: ptr(256)}, ptr(128), false},
		{KeyBits{Max: ptr(128)}, ptr(64), true},
		{KeyBits{Max: ptr(128)}, ptr(256), false},
	}
	for i, c := range cases {
		if got := c.kb.matches(c.bits); got != c.want {
			t.Errorf("case %d: matches = %v, want %v", i, got, c.want)
		}
	}
}
