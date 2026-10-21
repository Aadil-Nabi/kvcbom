package report_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
	"github.com/Aadil-Nabi/kvcbom/pkg/report"
	htmlrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/html"
	jsonrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/json"
	mdrender "github.com/Aadil-Nabi/kvcbom/pkg/report/render/md"
	"github.com/Aadil-Nabi/kvcbom/pkg/rulepack"
)

var update = flag.Bool("update", false, "update golden files")

func mkAsset(typ model.AssetType, name, oid, primitive string, conf model.ConfLevel, file, ref string) model.Asset {
	a := model.Asset{
		Type: typ, Name: name, OID: oid, Primitive: primitive,
		Evidence: []model.Evidence{{SourceType: model.SourceScannerCBOM, SourceFile: file, BOMRef: ref, Confidence: conf}},
	}
	a.ID = model.AssetIdentity(a)
	return a
}

// testReport builds a fixed, hermetic report (no file IO, fixed timestamp and pack sha) so
// golden files capture only intended changes.
func testReport(t *testing.T) *report.Report {
	t.Helper()
	assets := []model.Asset{
		mkAsset(model.AssetAlgorithm, "RSA-2048", "1.2.840.113549.1.1.1", "pke", model.C2, "bom.json", "alg:rsa"),
		mkAsset(model.AssetAlgorithm, "AES-256-GCM", "", "ae", model.C3, "bom.json", "alg:aes"),
		mkAsset(model.AssetAlgorithm, "SHA-1", "", "hash", model.C4, "bom.json", "alg:sha1"),
		mkAsset(model.AssetProtocol, "TLS 1.3", "", "", model.C1, "bom.json", "proto:tls"),
	}
	batch := &model.Batch{SourceFile: "bom.json", SourceSHA256: "sha-of-bom", Assets: assets}

	mig := 4.0
	ctx := &model.Context{
		Meta:                     model.AssessmentMeta{Organisation: "Example Corp", Assessor: "Sec Team", Scope: "Web tier"},
		GlobalMigrationTimeYears: 5,
		CRQCScenarios:            []model.CRQCScenario{{Name: "central", YearsUntil: 8}, {Name: "pessimistic", YearsUntil: 5}},
		DataClasses:              []model.DataClass{{ID: "pii", Name: "Personal Data", ConfidentialityLifetimeYears: 12}},
		Systems: []model.System{{
			ID: "web", Name: "Web Tier", Criticality: model.CriticalityCritical, CrownJewel: true,
			DataClassRefs: []string{"pii"}, MigrationTimeYears: &mig,
		}},
		LinkRules: []model.LinkRule{{SystemRef: "web", NamePatterns: []string{"(?i)rsa", "(?i)aes"}}},
	}

	lp, err := rulepack.LoadEmbedded("baseline-pqc")
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}

	rep, err := report.Build(report.Input{
		Title:       "Test Readiness Report",
		Assessment:  ctx.Meta,
		Batches:     []*model.Batch{batch},
		Context:     ctx,
		Pack:        lp.Pack,
		PackSHA256:  "test-pack-sha",
		Tool:        report.ToolInfo{Name: "kvcbom", Version: "1.0.0-test", Commit: "testcommit", Date: "2026-01-01"},
		GeneratedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return rep
}

func goldenCompare(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update to create): %v", name, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s does not match golden; run `go test ./pkg/report -update` if the change is intended", name)
	}
}

func TestGolden_JSON(t *testing.T) {
	rep := testReport(t)
	got, err := jsonrender.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	goldenCompare(t, "report.json", got)
}

func TestGolden_HTML(t *testing.T) {
	rep := testReport(t)
	var buf bytes.Buffer
	if err := (htmlrender.Renderer{}).Render(rep, &buf); err != nil {
		t.Fatal(err)
	}
	goldenCompare(t, "report.html", buf.Bytes())
}

func TestGolden_Markdown(t *testing.T) {
	rep := testReport(t)
	var buf bytes.Buffer
	if err := (mdrender.Renderer{}).Render(rep, &buf); err != nil {
		t.Fatal(err)
	}
	goldenCompare(t, "report.md", buf.Bytes())
}

func TestJSON_ValidatesAgainstSchema(t *testing.T) {
	rep := testReport(t)
	got, err := jsonrender.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := jsonrender.Validate(got); err != nil {
		t.Fatalf("canonical JSON does not conform to the output schema: %v", err)
	}
}

func TestBuild_Deterministic(t *testing.T) {
	a, err := jsonrender.Marshal(testReport(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := jsonrender.Marshal(testReport(t))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("two builds of the same inputs produced different JSON bytes")
	}
}

func TestBuild_PipelineShape(t *testing.T) {
	rep := testReport(t)

	if rep.Summary.TotalAssets != 4 {
		t.Errorf("total assets = %d, want 4", rep.Summary.TotalAssets)
	}
	// RSA (critical), SHA-1 (high), AES-256 (info/resistant), TLS (info/unclassified).
	if rep.Summary.TotalFindings != 4 {
		t.Errorf("total findings = %d, want 4", rep.Summary.TotalFindings)
	}

	// The RSA asset links to the crown-jewel web system and is HNDL-exposed.
	if rep.Summary.HNDLAssetCount < 1 {
		t.Errorf("expected at least one HNDL asset, got %d", rep.Summary.HNDLAssetCount)
	}
	if len(rep.Systems) != 1 || rep.Systems[0].System.ID != "web" {
		t.Fatalf("expected one system view for web, got %+v", rep.Systems)
	}
	if len(rep.Frameworks) != 0 {
		t.Error("baseline pack has no framework and no overlays were given; frameworks should be empty")
	}
	// Mosca aggregated for both scenarios.
	if len(rep.Summary.MoscaByScenario) != 2 {
		t.Errorf("expected 2 scenario outcomes, got %d", len(rep.Summary.MoscaByScenario))
	}
}

func TestBuild_MultiFramework(t *testing.T) {
	batch := &model.Batch{SourceFile: "bom.json", Assets: []model.Asset{
		mkAsset(model.AssetAlgorithm, "RSA-2048", "", "pke", model.C3, "bom.json", "alg:rsa"),
	}}
	classifier, _ := rulepack.LoadEmbedded("baseline-pqc")
	csa, _ := rulepack.LoadEmbedded("csa-qri-sg")
	nist, _ := rulepack.LoadEmbedded("nist-ir-8547")

	rep, err := report.Build(report.Input{
		Batches: []*model.Batch{batch}, Pack: classifier.Pack, PackSHA256: "x",
		Overlays: []*rulepack.Pack{csa.Pack, nist.Pack},
		Tool:     report.ToolInfo{Name: "kvcbom", Version: "t"}, GeneratedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Frameworks) != 2 {
		t.Fatalf("expected 2 framework views, got %d", len(rep.Frameworks))
	}
	// Overlays are sorted by id; each must have mapped the RSA key-establishment finding.
	for _, fw := range rep.Frameworks {
		var kex *report.FrameworkMappingView
		for i := range fw.Mappings {
			if fw.Mappings[i].FindingType == "quantum-vulnerable-key-establishment" {
				kex = &fw.Mappings[i]
			}
		}
		if kex == nil || kex.FindingCount != 1 {
			t.Errorf("%s: key-establishment mapping should count the RSA finding, got %+v", fw.ID, kex)
		}
		if !kex.Unverified {
			t.Errorf("%s: overlay control should be marked unverified (TODO)", fw.ID)
		}
	}
	// The report must warn that the framework mappings are unverified.
	warned := false
	for _, m := range rep.Warnings.Messages {
		if strings.Contains(m, "framework control mappings are unverified") {
			warned = true
		}
	}
	if !warned {
		t.Errorf("expected an unverified-framework warning, got %v", rep.Warnings.Messages)
	}
}

func TestBuild_NoContext(t *testing.T) {
	batch := &model.Batch{SourceFile: "bom.json", Assets: []model.Asset{
		mkAsset(model.AssetAlgorithm, "RSA-2048", "", "pke", model.C2, "bom.json", "alg:rsa"),
	}}
	lp, _ := rulepack.LoadEmbedded("baseline-pqc")
	rep, err := report.Build(report.Input{
		Batches: []*model.Batch{batch}, Pack: lp.Pack, PackSHA256: "x",
		Tool: report.ToolInfo{Name: "kvcbom", Version: "t"}, GeneratedAt: "2026-01-01T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Systems) != 0 || len(rep.Summary.MoscaByScenario) != 0 {
		t.Error("no context should yield no systems and no Mosca outcomes")
	}
	if rep.Title == "" {
		t.Error("expected a default title when none was given")
	}
	// Still produces the RSA finding.
	if rep.Summary.TotalFindings != 1 {
		t.Errorf("findings = %d, want 1", rep.Summary.TotalFindings)
	}
}
