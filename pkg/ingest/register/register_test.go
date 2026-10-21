package register

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/xuri/excelize/v2"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDefaultMapping_Parses(t *testing.T) {
	m := DefaultMapping()
	if m.ListDelimiter != ";" || !m.HeaderRow {
		t.Errorf("unexpected default mapping: %+v", m)
	}
	if m.Columns["name"] != "Name" {
		t.Errorf("default mapping missing name column: %+v", m.Columns)
	}
}

func TestParseMapping_UnknownFieldRejected(t *testing.T) {
	if _, err := parseMapping([]byte("columns:\n  not_a_field: X\n")); err == nil {
		t.Fatal("expected an error for an unknown mapping field")
	}
}

func TestIngestCSV(t *testing.T) {
	csv := "Name,Type,Key Size (bits),Functions,Confidence,Systems\n" +
		"RSA-2048,algorithm,2048,verify;sign,C3,payments\n" +
		"AES-256,algorithm,256,encrypt,,\n" +
		",,,,,\n"
	p := writeTemp(t, "reg.csv", []byte(csv))

	res, err := IngestFile(p, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Batch.Assets) != 2 {
		t.Fatalf("asset count = %d, want 2 (blank row skipped)", len(res.Batch.Assets))
	}

	var rsa *model.Asset
	for i := range res.Batch.Assets {
		if res.Batch.Assets[i].Name == "RSA-2048" {
			rsa = &res.Batch.Assets[i]
		}
	}
	if rsa == nil {
		t.Fatal("RSA asset not found")
	}
	if rsa.KeySizeBits == nil || *rsa.KeySizeBits != 2048 {
		t.Errorf("RSA key size = %v, want 2048", rsa.KeySizeBits)
	}
	if !reflect.DeepEqual(rsa.Functions, []string{"sign", "verify"}) {
		t.Errorf("functions = %v, want sorted [sign verify]", rsa.Functions)
	}
	if !reflect.DeepEqual(rsa.SystemRefs, []string{"payments"}) {
		t.Errorf("system refs = %v", rsa.SystemRefs)
	}
	if len(rsa.Evidence) != 1 || rsa.Evidence[0].SourceType != model.SourceManualRegister {
		t.Errorf("evidence = %+v, want one manual-register record", rsa.Evidence)
	}
	if rsa.Evidence[0].Confidence != model.C3 {
		t.Errorf("confidence = %v, want C3", rsa.Evidence[0].Confidence)
	}

	// AES row had no confidence -> default C1.
	for _, a := range res.Batch.Assets {
		if a.Name == "AES-256" && a.Evidence[0].Confidence != model.C1 {
			t.Errorf("AES confidence = %v, want default C1", a.Evidence[0].Confidence)
		}
	}
}

func TestIngestXLSX(t *testing.T) {
	f := excelize.NewFile()
	sheet := f.GetSheetName(0)
	_ = f.SetSheetRow(sheet, "A1", &[]any{"Name", "Type", "Key Size (bits)", "Confidence"})
	_ = f.SetSheetRow(sheet, "A2", &[]any{"ECDSA P-256", "algorithm", "", "C2"})
	buf, err := f.WriteToBuffer()
	if err != nil {
		t.Fatal(err)
	}
	p := writeTemp(t, "reg.xlsx", buf.Bytes())

	res, err := IngestFile(p, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Batch.Assets) != 1 {
		t.Fatalf("asset count = %d, want 1", len(res.Batch.Assets))
	}
	a := res.Batch.Assets[0]
	if a.Name != "ECDSA P-256" || a.Evidence[0].Confidence != model.C2 {
		t.Errorf("unexpected asset: %+v", a)
	}
}

func TestIngest_MissingHeaderWarns(t *testing.T) {
	// Sheet lacks several mapped columns; ingest should warn, not fail.
	csv := "Name\nRSA-2048\n"
	p := writeTemp(t, "reg.csv", []byte(csv))
	res, err := IngestFile(p, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected warnings for missing mapped columns")
	}
	if len(res.Batch.Assets) != 1 {
		t.Fatalf("asset count = %d, want 1", len(res.Batch.Assets))
	}
}

func TestIngest_CustomMapping(t *testing.T) {
	m, err := parseMapping([]byte("columns:\n  name: \"Algo\"\n  confidence: \"Conf\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	csv := "Algo,Conf\nSHA-256,C4\n"
	p := writeTemp(t, "reg.csv", []byte(csv))
	res, err := IngestFile(p, m, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Batch.Assets) != 1 || res.Batch.Assets[0].Name != "SHA-256" {
		t.Fatalf("custom mapping failed: %+v", res.Batch.Assets)
	}
	if res.Batch.Assets[0].Evidence[0].Confidence != model.C4 {
		t.Errorf("confidence = %v, want C4", res.Batch.Assets[0].Evidence[0].Confidence)
	}
}

func TestIngest_UnknownFormat(t *testing.T) {
	p := writeTemp(t, "reg.txt", []byte("whatever"))
	if _, err := IngestFile(p, nil, Options{}); err == nil {
		t.Fatal("expected an unknown-format error")
	}
}

func TestIngest_Deterministic(t *testing.T) {
	csv := "Name,Confidence\nRSA-2048,C3\nAES-256,C2\n"
	p := writeTemp(t, "reg.csv", []byte(csv))
	a, _ := IngestFile(p, nil, Options{})
	b, _ := IngestFile(p, nil, Options{})
	if !reflect.DeepEqual(a.Batch, b.Batch) {
		t.Error("register ingest is not deterministic")
	}
}

func FuzzParseRegisterCSV(f *testing.F) {
	f.Add([]byte("Name,Confidence\nRSA,C2\n"))
	f.Add([]byte(""))
	f.Add([]byte("\"unterminated"))
	m := DefaultMapping()
	f.Fuzz(func(t *testing.T, data []byte) {
		rows, err := readCSV(data, DefaultMaxRows)
		if err != nil {
			return
		}
		// Must not panic turning arbitrary rows into a batch.
		_, _ = rowsToBatch(rows, m, Options{}.withDefaults(), "fuzz.csv")
	})
}
