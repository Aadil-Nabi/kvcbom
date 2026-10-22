package main

import (
	"os"
	"path/filepath"

	goyaml "github.com/goccy/go-yaml"

	"github.com/Aadil-Nabi/kvcbom/internal/cli"
	"github.com/Aadil-Nabi/kvcbom/internal/safety"
)

// maxConfigBytes caps the size of a --config file; a report profile is tiny.
const maxConfigBytes int64 = 1 << 20

// defaultConfigNames are the profile filenames `report` auto-loads from the current
// directory when no --config is given.
var defaultConfigNames = []string{"kvcbom.yaml", "kvcbom.yml"}

// findDefaultConfig returns the first default profile present in the current directory, or
// "" if none exists.
func findDefaultConfig() string {
	for _, n := range defaultConfigNames {
		if fi, err := os.Stat(n); err == nil && !fi.IsDir() {
			return n
		}
	}
	return ""
}

// reportConfig is a report "profile": the same inputs and options as the report flags,
// gathered into a YAML file so a long invocation becomes `report --config kvcbom.yaml`.
// Keys mirror the flag names. An explicit flag always overrides the file (flags > config).
type reportConfig struct {
	CBOM            []string `yaml:"cbom"`
	Register        string   `yaml:"register"`
	RegisterMapping string   `yaml:"register-mapping"`
	Context         string   `yaml:"context"`
	Rulepack        string   `yaml:"rulepack"`
	Framework       []string `yaml:"framework"`
	Format          []string `yaml:"format"`
	Out             string   `yaml:"out"`
	Title           string   `yaml:"title"`
	Org             string   `yaml:"org"`
	Timestamp       string   `yaml:"timestamp"`
	Force           *bool    `yaml:"force"`
	FailOn          string   `yaml:"fail-on"`
	PDFEngine       string   `yaml:"pdf-engine"`
	CBOMMapping     string   `yaml:"cbom-mapping"`
}

// loadReportConfig reads and parses a profile file, returning it with its directory so
// relative input/output paths can be resolved against the file's location (not the CWD),
// keeping a profile portable.
func loadReportConfig(path string) (*reportConfig, string, error) {
	data, err := safety.ReadFileLimited(path, maxConfigBytes)
	if err != nil {
		return nil, "", cli.Coded(cli.ExitValidation, err)
	}
	var cfg reportConfig
	if err := goyaml.Unmarshal(data, &cfg); err != nil {
		return nil, "", cli.Codedf(cli.ExitValidation, "config %s: %v", path, err)
	}
	return &cfg, filepath.Dir(path), nil
}

// resolveUnder resolves a possibly-relative path against baseDir (the config file's
// directory). Absolute paths and empty strings are returned unchanged.
func resolveUnder(baseDir, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(baseDir, p)
}
