package cbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/internal/safety"
)

// seedCorpus reads every testdata file matching the glob and adds it to the fuzz corpus.
func seedCorpus(f *testing.F, glob string) {
	f.Helper()
	matches, err := filepath.Glob(filepath.Join("testdata", glob))
	if err != nil {
		f.Fatalf("glob: %v", err)
	}
	for _, m := range matches {
		b, err := os.ReadFile(m) //nolint:gosec // test-controlled path
		if err != nil {
			f.Fatalf("read %s: %v", m, err)
		}
		f.Add(b)
	}
}

// fuzzParse runs the decode+normalise pipeline on arbitrary input for one format and
// asserts only that it never panics and returns a usable batch on success. Malformed
// input must produce an error, not a crash.
func fuzzParse(t *testing.T, data []byte, format safety.Format) {
	t.Helper()
	bom, err := decode(data, format)
	if err != nil {
		return
	}
	b := normalise(bom, "fuzz", "", Options{}.withDefaults())
	if b == nil {
		t.Fatal("normalise returned nil batch for a successfully decoded BOM")
	}
	// Completeness must also be panic-free on whatever normalise produced.
	_ = checkCompleteness(b)
}

func FuzzParseCBOMJSON(f *testing.F) {
	seedCorpus(f, "*.json")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzParse(t, data, safety.FormatJSON)
	})
}

func FuzzParseCBOMXML(f *testing.F) {
	seedCorpus(f, "*.xml")
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzParse(t, data, safety.FormatXML)
	})
}
