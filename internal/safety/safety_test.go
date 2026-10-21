package safety

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFormat_ByExtension(t *testing.T) {
	cases := map[string]Format{
		"a.json": FormatJSON,
		"a.xml":  FormatXML,
		"a.JSON": FormatJSON,
	}
	for name, want := range cases {
		if got := DetectFormat(name, nil); got != want {
			t.Errorf("DetectFormat(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestDetectFormat_ByContent(t *testing.T) {
	cases := []struct {
		data []byte
		want Format
	}{
		{[]byte("   \n\t{"), FormatJSON},
		{[]byte("\n["), FormatJSON},
		{[]byte("  <bom"), FormatXML},
		{[]byte("plain text"), FormatUnknown},
		{[]byte(""), FormatUnknown},
	}
	for _, c := range cases {
		if got := DetectFormat("noext", c.data); got != c.want {
			t.Errorf("DetectFormat(content %q) = %v, want %v", c.data, got, c.want)
		}
	}
}

func TestDetectFormat_SkipsUTF8BOM(t *testing.T) {
	data := append([]byte{0xEF, 0xBB, 0xBF}, []byte("{}")...)
	if got := DetectFormat("noext", data); got != FormatJSON {
		t.Errorf("DetectFormat with UTF-8 BOM = %v, want json", got)
	}
}

func TestReadFileLimited_RejectsOversize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "big.json")
	if err := os.WriteFile(p, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileLimited(p, 5); err == nil {
		t.Fatal("expected ErrTooLarge for a file above the limit")
	}
	if _, err := ReadFileLimited(p, 100); err != nil {
		t.Fatalf("unexpected error under the limit: %v", err)
	}
}

func TestWithinBase(t *testing.T) {
	base := t.TempDir()
	if _, ok := WithinBase(base, "report.pdf"); !ok {
		t.Error("a plain child path should be within base")
	}
	if _, ok := WithinBase(base, filepath.Join("..", "..", "etc", "passwd")); ok {
		t.Error("a traversal path must be rejected")
	}
}
