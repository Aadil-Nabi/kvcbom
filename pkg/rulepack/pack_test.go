package rulepack

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/rulepacks"
)

func TestLoadPath_And_Load(t *testing.T) {
	// Write the embedded baseline to disk and load it by path.
	data, ok := rulepacks.Read("baseline-pqc")
	if !ok {
		t.Fatal("embedded baseline not found")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "my-pack.yaml")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}

	lp, err := Load(p) // existing file -> LoadPath
	if err != nil {
		t.Fatalf("Load(path): %v", err)
	}
	if lp.Origin != p {
		t.Errorf("origin = %q, want the file path", lp.Origin)
	}
	if lp.SHA256 == "" {
		t.Error("loaded pack should record a source SHA-256")
	}
	if len(lp.Pack.Validate()) != 0 {
		t.Error("disk-loaded baseline should validate clean")
	}
}

func TestLoad_DirectoryRejected(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("expected directory packs to be rejected")
	}
}

func TestValidationError(t *testing.T) {
	if err := ValidationError(nil); err != nil {
		t.Errorf("no issues should yield nil error, got %v", err)
	}
	issues := []PackIssue{
		{Level: LevelWarn, Location: "x", Message: "just a warning"},
	}
	if err := ValidationError(issues); err != nil {
		t.Errorf("only warnings should yield nil error, got %v", err)
	}
	issues = append(issues, PackIssue{Level: LevelError, Location: "y", Message: "real problem"})
	if err := ValidationError(issues); err == nil {
		t.Error("an error-level issue should yield a non-nil error")
	}
}

func TestPack_Getters(t *testing.T) {
	p := loadBaseline(t)

	if _, ok := p.Remediation("migrate-asymmetric-to-pqc"); !ok {
		t.Error("expected to find the migrate-asymmetric-to-pqc remediation")
	}
	if _, ok := p.Remediation("does-not-exist"); ok {
		t.Error("unexpected remediation found")
	}
	if len(p.RemediationIDs()) == 0 {
		t.Error("expected remediation ids")
	}
	if w := p.Scoring().Weights; w["quantum_vulnerability"] == 0 {
		t.Error("expected scoring weights to be populated")
	}
	if len(p.FrameworkMappings()) != 0 {
		t.Error("baseline should have no framework mappings")
	}
	if len(p.Rules()) == 0 || len(p.Sources()) == 0 {
		t.Error("expected rules and sources")
	}
}

func TestSeveritySorted(t *testing.T) {
	sevs := []Severity{SevLow, SevCritical, SevInfo, SevHigh, SevMedium}
	SeveritySorted(sevs)
	want := []Severity{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}
	for i := range want {
		if sevs[i] != want[i] {
			t.Fatalf("SeveritySorted = %v, want %v", sevs, want)
		}
	}
}

// A pack exercising framework mappings and classification milestones, to cover those
// validation paths.
const frameworkPack = `
schema_version: 1
id: fwk-pack
version: 1.0.0
name: Framework Pack
status: draft
sources:
  - id: src1
    title: Primary
    url: https://example.com
    status: final
classifications:
  - id: c1
    quantum_status: shor_broken
    source: src1
    deprecation:
      date: "TODO(source): date"
      source: src1
    disallowance:
      date: "2035-01-01"
      source: ghost-source
    match:
      name_patterns: ["(?i)rsa"]
framework:
  id: demo-fwk
  name: Demo Framework
  mappings:
    - finding_type: quantum-vulnerable-asymmetric
      control_id: "TODO(source): control id"
      source: ghost-source
`

func TestValidate_FrameworkAndMilestones(t *testing.T) {
	p := mustLoadBytes(t, frameworkPack)
	issues := p.Validate()

	// Dangling disallowance source and dangling mapping source are errors.
	if countErrors(issues) < 2 {
		t.Errorf("expected at least two errors (dangling milestone + mapping source), got: %v", issues)
	}
	// TODO markers in the deprecation date and control id are warnings.
	warns := 0
	for _, i := range issues {
		if i.Level == LevelWarn {
			warns++
		}
	}
	if warns < 2 {
		t.Errorf("expected TODO warnings for deprecation date and control id, got: %v", issues)
	}
	if !p.HasUnverifiedContent() {
		t.Error("draft pack with TODO markers must report unverified content")
	}
	if fm := p.FrameworkMappings(); len(fm) != 1 || fm[0].FindingType != "quantum-vulnerable-asymmetric" {
		t.Errorf("unexpected framework mappings: %+v", fm)
	}
}
