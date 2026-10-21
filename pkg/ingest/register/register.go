package register

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/Aadil-Nabi/kvcbom/internal/hashid"
	"github.com/Aadil-Nabi/kvcbom/internal/safety"
	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

// Default limits. The register is untrusted input (SPEC §5.4): cap the file size and the
// number of rows and cells so a crafted spreadsheet cannot exhaust memory.
const (
	DefaultMaxInputBytes int64 = 32 << 20 // 32 MiB
	DefaultMaxRows             = 100_000
)

var (
	// ErrUnknownFormat is returned for a file that is neither .csv nor .xlsx.
	ErrUnknownFormat = errors.New("unsupported register format (expected .csv or .xlsx)")
	// ErrTooManyRows is returned when a sheet exceeds the row limit.
	ErrTooManyRows = errors.New("register exceeds the maximum row count")
)

// Options controls register ingest.
type Options struct {
	MaxInputBytes int64
	MaxRows       int
	// DefaultConfidence is used when a row has no confidence value. Register entries are
	// asserted/manual, so the default is the weakest level unless the sheet says otherwise.
	DefaultConfidence model.ConfLevel
}

func (o Options) withDefaults() Options {
	if o.MaxInputBytes <= 0 {
		o.MaxInputBytes = DefaultMaxInputBytes
	}
	if o.MaxRows <= 0 {
		o.MaxRows = DefaultMaxRows
	}
	if !o.DefaultConfidence.Valid() {
		o.DefaultConfidence = model.C1
	}
	return o
}

// Result is the outcome of ingesting one register file.
type Result struct {
	Batch    *model.Batch
	SHA256   string
	Warnings []string // e.g. a mapped header that the sheet does not contain
}

// IngestFile reads a register file, maps its rows to assets, and returns a batch. A nil
// mapping uses the built-in default.
func IngestFile(path string, m *Mapping, opts Options) (*Result, error) {
	opts = opts.withDefaults()
	if m == nil {
		m = DefaultMapping()
	}

	data, err := safety.ReadFileLimited(path, opts.MaxInputBytes)
	if err != nil {
		return nil, err
	}

	var rows [][]string
	switch strings.ToLower(filepath.Ext(path)) {
	case ".csv":
		rows, err = readCSV(data, opts.MaxRows)
	case ".xlsx":
		rows, err = readXLSX(data, m.Sheet, opts.MaxRows)
	default:
		return nil, fmt.Errorf("%s: %w", path, ErrUnknownFormat)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	batch, warnings := rowsToBatch(rows, m, opts, path)
	batch.SourceSHA256 = hashid.SHA256Hex(data)
	return &Result{Batch: batch, SHA256: batch.SourceSHA256, Warnings: warnings}, nil
}

func readCSV(data []byte, maxRows int) ([][]string, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1 // tolerate ragged rows
	var rows [][]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse CSV: %w", err)
		}
		rows = append(rows, rec)
		if len(rows) > maxRows {
			return nil, ErrTooManyRows
		}
	}
	return rows, nil
}

func readXLSX(data []byte, sheet string, maxRows int) ([][]string, error) {
	f, err := excelize.OpenReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open XLSX: %w", err)
	}
	defer f.Close()

	if sheet == "" {
		sheet = f.GetSheetName(0)
		if sheet == "" {
			return nil, fmt.Errorf("XLSX has no sheets")
		}
	}
	rows, err := f.GetRows(sheet)
	if err != nil {
		return nil, fmt.Errorf("read sheet %q: %w", sheet, err)
	}
	if len(rows) > maxRows {
		return nil, ErrTooManyRows
	}
	return rows, nil
}

// rowsToBatch turns raw rows into a sorted batch of assets. The first row is the header.
func rowsToBatch(rows [][]string, m *Mapping, opts Options, path string) (*model.Batch, []string) {
	b := &model.Batch{SourceFile: path}
	if len(rows) == 0 {
		return b, nil
	}

	// Map each logical field to a 0-based column index via the header row.
	header := rows[0]
	headerIndex := map[string]int{}
	for i, h := range header {
		headerIndex[strings.ToLower(strings.TrimSpace(h))] = i
	}

	var warnings []string
	colOf := map[string]int{} // field -> column index, when present
	for field, label := range m.Columns {
		if idx, ok := headerIndex[strings.ToLower(strings.TrimSpace(label))]; ok {
			colOf[field] = idx
		} else {
			warnings = append(warnings, fmt.Sprintf("column %q for field %q not found in the register header", label, field))
		}
	}
	sort.Strings(warnings)

	get := func(row []string, field string) string {
		idx, ok := colOf[field]
		if !ok || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	for _, row := range rows[1:] {
		a, ok := buildAsset(row, m, opts, path, get)
		if ok {
			b.Assets = append(b.Assets, a)
		}
	}

	sort.Slice(b.Assets, func(i, j int) bool {
		if b.Assets[i].ID != b.Assets[j].ID {
			return b.Assets[i].ID < b.Assets[j].ID
		}
		return b.Assets[i].Name < b.Assets[j].Name
	})
	return b, warnings
}

func buildAsset(row []string, m *Mapping, opts Options, path string, get func([]string, string) string) (model.Asset, bool) {
	a := model.Asset{
		Name:            get(row, fieldName),
		Type:            parseType(get(row, fieldType)),
		AlgorithmFamily: get(row, fieldAlgoFamily),
		ParameterSet:    get(row, fieldParameterSet),
		Mode:            get(row, fieldMode),
		Primitive:       get(row, fieldPrimitive),
		Curve:           get(row, fieldCurve),
		OID:             get(row, fieldOID),
		Implementation:  get(row, fieldImplementation),
	}
	if k, ok := parseInt(get(row, fieldKeySizeBits)); ok {
		a.KeySizeBits = &k
	}
	a.Functions = splitList(get(row, fieldFunctions), m.ListDelimiter)
	if loc := get(row, fieldLocation); loc != "" {
		a.Locations = []string{loc}
	}
	a.SystemRefs = splitList(get(row, fieldSystemRefs), m.ListDelimiter)
	a.DataClassRefs = splitList(get(row, fieldDataClassRefs), m.ListDelimiter)

	// A row with no identifying content at all is skipped (blank spreadsheet line).
	if a.Name == "" && a.AlgorithmFamily == "" && a.ParameterSet == "" && a.OID == "" &&
		a.Primitive == "" && a.Curve == "" && a.KeySizeBits == nil {
		return model.Asset{}, false
	}

	conf := opts.DefaultConfidence
	if c, ok := parseConfidence(get(row, fieldConfidence)); ok {
		conf = c
	}
	a.Evidence = []model.Evidence{{
		SourceType: model.SourceManualRegister,
		SourceFile: path,
		Confidence: conf,
	}}
	a.ID = model.AssetIdentity(a)
	return a, true
}

func parseType(s string) model.AssetType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "algorithm":
		return model.AssetAlgorithm
	case "certificate":
		return model.AssetCertificate
	case "protocol":
		return model.AssetProtocol
	case "related-crypto-material", "related crypto material", "key", "key-material":
		return model.AssetRelatedCryptoMaterial
	default:
		return model.AssetUnknown
	}
}

func parseInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// parseConfidence accepts "C1".."C4" or "1".."4" (case-insensitive).
func parseConfidence(s string) (model.ConfLevel, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "C")
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	c := model.ConfLevel(n)
	if !c.Valid() {
		return 0, false
	}
	return c, true
}

func splitList(s, delim string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, delim)
	var out []string
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}
