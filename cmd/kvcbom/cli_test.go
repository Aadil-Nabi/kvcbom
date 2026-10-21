package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/Aadil-Nabi/kvcbom/internal/cli"
)

// minimal valid 1.6 CBOMs used by the exit-code tests.
const rsaCBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "components": [{
    "type": "cryptographic-asset", "bom-ref": "alg:rsa", "name": "RSA-2048",
    "cryptoProperties": {"assetType": "algorithm",
      "algorithmProperties": {"primitive": "pke", "parameterSetIdentifier": "2048"},
      "oid": "1.2.840.113549.1.1.1"}
  }]
}`

const kemCBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "components": [{
    "type": "cryptographic-asset", "bom-ref": "alg:kem", "name": "ML-KEM-768",
    "cryptoProperties": {"assetType": "algorithm",
      "algorithmProperties": {"primitive": "kem", "parameterSetIdentifier": "ML-KEM-768"}}
  }]
}`

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// run executes a freshly-built command with args, discarding output, and returns the exit
// code the CLI would produce.
func run(cmd *cobra.Command, args ...string) int {
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cli.CodeOf(cmd.Execute())
}

func TestReport_FailOnExitCodes(t *testing.T) {
	dir := t.TempDir()
	cbom := writeFile(t, dir, "rsa.cbom.json", rsaCBOM)

	// No threshold: success.
	if code := run(newReportCmd(), "--cbom", cbom, "--out", filepath.Join(dir, "o1"), "--format", "json", "--timestamp", "2026-01-01T00:00:00Z"); code != cli.ExitOK {
		t.Errorf("no --fail-on: exit %d, want %d", code, cli.ExitOK)
	}
	// RSA yields a critical finding -> --fail-on critical breaches -> exit 3.
	if code := run(newReportCmd(), "--cbom", cbom, "--out", filepath.Join(dir, "o2"), "--format", "json", "--fail-on", "critical", "--timestamp", "2026-01-01T00:00:00Z"); code != cli.ExitPolicy {
		t.Errorf("--fail-on critical: exit %d, want %d", code, cli.ExitPolicy)
	}
	// Outputs are still written before the policy gate fails.
	if _, err := os.Stat(filepath.Join(dir, "o2", "report.json")); err != nil {
		t.Errorf("report.json should be written even when the policy gate fails: %v", err)
	}
	// Invalid threshold value -> usage error.
	if code := run(newReportCmd(), "--cbom", cbom, "--out", filepath.Join(dir, "o3"), "--fail-on", "nonsense", "--timestamp", "2026-01-01T00:00:00Z"); code != cli.ExitUsage {
		t.Errorf("bad --fail-on: exit %d, want %d", code, cli.ExitUsage)
	}
}

func TestReport_UsageErrors(t *testing.T) {
	if code := run(newReportCmd(), "--out", t.TempDir()); code != cli.ExitUsage {
		t.Errorf("no --cbom/--register: exit %d, want %d", code, cli.ExitUsage)
	}
	dir := t.TempDir()
	cbom := writeFile(t, dir, "rsa.cbom.json", rsaCBOM)
	if code := run(newReportCmd(), "--cbom", cbom); code != cli.ExitUsage {
		t.Errorf("no --out: exit %d, want %d", code, cli.ExitUsage)
	}
}

func TestReport_SchemaToleranceAndHardFailure(t *testing.T) {
	dir := t.TempDir()

	// A schema non-conformance that still decodes (wrong bomFormat) is tolerated by report:
	// it becomes a warning, not a fatal error. (validate is the strict gate.)
	schemaBad := writeFile(t, dir, "schemabad.json", `{"bomFormat":"NotCycloneDX","specVersion":"1.6","version":1}`)
	out := filepath.Join(dir, "o-schema")
	if code := run(newReportCmd(), "--cbom", schemaBad, "--out", out, "--format", "json", "--timestamp", "2026-01-01T00:00:00Z"); code != cli.ExitOK {
		t.Errorf("schema-nonconformant but decodable CBOM: exit %d, want %d", code, cli.ExitOK)
	}
	data, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("did not fully conform")) {
		t.Error("expected a schema non-conformance warning in the report")
	}

	// A file that cannot be decoded at all is a hard input failure (exit 2).
	garbage := writeFile(t, dir, "garbage.txt", "this is not a CBOM")
	if code := run(newReportCmd(), "--cbom", garbage, "--out", filepath.Join(dir, "o-garbage"), "--timestamp", "2026-01-01T00:00:00Z"); code != cli.ExitValidation {
		t.Errorf("undecodable CBOM: exit %d, want %d", code, cli.ExitValidation)
	}
}

func TestDiff_UsageAndRegression(t *testing.T) {
	dir := t.TempDir()
	rsa := writeFile(t, dir, "rsa.cbom.json", rsaCBOM)
	kem := writeFile(t, dir, "kem.cbom.json", kemCBOM)

	// Missing args -> usage.
	if code := run(newDiffCmd()); code != cli.ExitUsage {
		t.Errorf("diff no args: exit %d, want %d", code, cli.ExitUsage)
	}

	// Build a baseline (resistant only) and a current (adds a critical RSA finding).
	baseOut := filepath.Join(dir, "base")
	curOut := filepath.Join(dir, "cur")
	if code := run(newReportCmd(), "--cbom", kem, "--out", baseOut, "--format", "json", "--timestamp", "2026-01-01T00:00:00Z"); code != cli.ExitOK {
		t.Fatalf("baseline report failed: exit %d", code)
	}
	if code := run(newReportCmd(), "--cbom", kem, "--cbom", rsa, "--out", curOut, "--format", "json", "--timestamp", "2026-02-01T00:00:00Z"); code != cli.ExitOK {
		t.Fatalf("current report failed: exit %d", code)
	}

	base := filepath.Join(baseOut, "report.json")
	cur := filepath.Join(curOut, "report.json")

	// Plain diff succeeds (exit 0).
	if code := run(newDiffCmd(), "--baseline", base, "--current", cur); code != cli.ExitOK {
		t.Errorf("diff: exit %d, want %d", code, cli.ExitOK)
	}
	// Risk rose (new critical finding) -> --fail-on-regression exits 3.
	if code := run(newDiffCmd(), "--baseline", base, "--current", cur, "--fail-on-regression"); code != cli.ExitPolicy {
		t.Errorf("diff --fail-on-regression: exit %d, want %d", code, cli.ExitPolicy)
	}
	// Comparing a report with itself -> no regression -> exit 0.
	if code := run(newDiffCmd(), "--baseline", cur, "--current", cur, "--fail-on-regression"); code != cli.ExitOK {
		t.Errorf("diff self --fail-on-regression: exit %d, want %d", code, cli.ExitOK)
	}
}
