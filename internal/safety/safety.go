// Package safety holds the guards applied to every untrusted input: size limits,
// format detection, safe XML decoding, and path-containment checks. All inputs to
// kvcbom are treated as hostile.
package safety

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DefaultMaxInputBytes is the default per-file size ceiling. CBOMs are text and rarely
// large; a generous but bounded limit stops a single file exhausting memory.
const DefaultMaxInputBytes int64 = 64 << 20 // 64 MiB

// ErrTooLarge is returned when an input exceeds the configured size limit.
var ErrTooLarge = errors.New("input exceeds maximum allowed size")

// Format identifies how an input is encoded.
type Format int

const (
	FormatUnknown Format = iota
	FormatJSON
	FormatXML
)

func (f Format) String() string {
	switch f {
	case FormatJSON:
		return "json"
	case FormatXML:
		return "xml"
	default:
		return "unknown"
	}
}

// ReadFileLimited reads path into memory, refusing files larger than max bytes. It
// stats first (cheap rejection) and still caps the read so a lying/racing size can't
// exceed the limit.
func ReadFileLimited(path string, max int64) ([]byte, error) {
	if max <= 0 {
		max = DefaultMaxInputBytes
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a file", path)
	}
	if fi.Size() > max {
		return nil, fmt.Errorf("%s (%d bytes): %w of %d bytes", path, fi.Size(), ErrTooLarge, max)
	}
	f, err := os.Open(path) //nolint:gosec // path is an explicit CLI argument
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// Read up to max+1 so we can detect a file that grew past the limit after stat.
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s: %w of %d bytes", path, ErrTooLarge, max)
	}
	return data, nil
}

// DetectFormat decides whether data is JSON or XML, preferring the file extension and
// falling back to the first non-whitespace byte.
func DetectFormat(path string, data []byte) Format {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return FormatJSON
	case ".xml":
		return FormatXML
	}
	for _, b := range TrimBOM(data) {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{', '[':
			return FormatJSON
		case '<':
			return FormatXML
		default:
			return FormatUnknown
		}
	}
	return FormatUnknown
}

// NewSafeXMLDecoder returns an xml.Decoder configured defensively. Go's encoding/xml
// does not resolve DTDs or external entities, so XML external-entity (XXE) attacks are
// not possible; we additionally run in Strict mode and clear the custom-entity map.
func NewSafeXMLDecoder(r io.Reader) *xml.Decoder {
	d := xml.NewDecoder(r)
	d.Strict = true
	d.Entity = map[string]string{} // only the five predefined XML entities are honoured
	return d
}

// WithinBase reports whether target resolves to a path inside base. It is used before
// writing any file whose name is influenced by input, to prevent path traversal.
func WithinBase(base, target string) (string, bool) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", false
	}
	joined := filepath.Join(absBase, filepath.FromSlash(target))
	cleaned := filepath.Clean(joined)
	rel, err := filepath.Rel(absBase, cleaned)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return cleaned, true
}

// TrimBOM removes a leading UTF-8 byte-order mark if present.
func TrimBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF})
}
