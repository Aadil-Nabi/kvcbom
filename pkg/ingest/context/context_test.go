package context

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Aadil-Nabi/kvcbom/pkg/model"
)

func loadCtx(t *testing.T) *model.Context {
	t.Helper()
	res, err := LoadFile(filepath.Join("testdata", "context.yaml"))
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return res.Context
}

func TestLoadFile_ParsesContext(t *testing.T) {
	res, err := LoadFile(filepath.Join("testdata", "context.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	c := res.Context
	if c.Meta.Organisation != "Example Corp" {
		t.Errorf("organisation = %q", c.Meta.Organisation)
	}
	if c.GlobalMigrationTimeYears != 5 {
		t.Errorf("global migration = %v, want 5", c.GlobalMigrationTimeYears)
	}
	if len(c.CRQCScenarios) != 3 || len(c.Systems) != 2 || len(c.DataClasses) != 2 {
		t.Fatalf("unexpected counts: %d scenarios, %d systems, %d data classes",
			len(c.CRQCScenarios), len(c.Systems), len(c.DataClasses))
	}
	if res.SHA256 == "" {
		t.Error("expected a source SHA-256")
	}
	if sys, ok := c.SystemByID("payments"); !ok || !sys.CrownJewel || sys.Criticality != model.CriticalityCritical {
		t.Errorf("payments system not parsed correctly: %+v", sys)
	}
}

func TestLoadFile_CompleteContextHasNoIssues(t *testing.T) {
	res, _ := LoadFile(filepath.Join("testdata", "context.yaml"))
	if len(res.Completeness) != 0 {
		t.Errorf("expected no completeness issues, got %v", res.Completeness)
	}
}

func TestParse_SchemaErrors(t *testing.T) {
	cases := map[string]string{
		"missing schema_version": "global_migration_time_years: 5\ncrqc_scenarios: [{name: a, years_until: 10}]\n",
		"no scenarios":           "schema_version: 1\nglobal_migration_time_years: 5\ncrqc_scenarios: []\n",
		"bad criticality":        "schema_version: 1\nglobal_migration_time_years: 5\ncrqc_scenarios: [{name: a, years_until: 10}]\nsystems: [{id: s, name: S, criticality: extreme}]\n",
		"unknown field":          "schema_version: 1\nglobal_migration_time_years: 5\ncrqc_scenarios: [{name: a, years_until: 10}]\nbogus: 1\n",
	}
	for name, y := range cases {
		if _, err := parse([]byte(y)); err == nil {
			t.Errorf("%s: expected a schema error", name)
		}
	}
}

func TestCompleteness_MinimalContextWarns(t *testing.T) {
	y := "schema_version: 1\nglobal_migration_time_years: 0\ncrqc_scenarios: [{name: central, years_until: 10}]\n"
	c, err := parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	issues := checkCompleteness(c)
	wantLocs := map[string]bool{"systems": false, "data_classes": false, "link_rules": false, "global_migration_time_years": false}
	for _, is := range issues {
		if _, ok := wantLocs[is.Location]; ok {
			wantLocs[is.Location] = true
		}
	}
	for loc, found := range wantLocs {
		if !found {
			t.Errorf("expected a completeness issue for %q", loc)
		}
	}
}

func TestCompleteness_DanglingRefs(t *testing.T) {
	y := `schema_version: 1
global_migration_time_years: 5
crqc_scenarios: [{name: central, years_until: 10}]
systems:
  - id: s1
    name: S1
    criticality: high
    data_class_refs: [missing-dc]
link_rules:
  - system_ref: no-such-system
    name_patterns: ["(?i)rsa"]
`
	c, err := parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	issues := checkCompleteness(c)
	foundDC, foundSys := false, false
	for _, is := range issues {
		if is.Location == `system "s1"` {
			foundDC = true
		}
		if is.Location == "link_rule #1" {
			foundSys = true
		}
	}
	if !foundDC {
		t.Error("expected a warning for the dangling data class ref")
	}
	if !foundSys {
		t.Error("expected a warning for the dangling system ref in the link rule")
	}
}

func TestLink_AttachesSystemsAndDataClasses(t *testing.T) {
	c := loadCtx(t)
	assets := []model.Asset{
		{ID: "a1", Name: "RSA-2048", Evidence: []model.Evidence{{BOMRef: "alg:rsa"}}},
		{ID: "a2", Name: "AES-256-GCM", Evidence: []model.Evidence{{BOMRef: "alg:aes-logging"}}},
		{ID: "a3", Name: "ML-KEM-768", Evidence: []model.Evidence{{BOMRef: "alg:kem"}}},
	}
	linked, err := Link(assets, c)
	if err != nil {
		t.Fatal(err)
	}

	// RSA matched by name pattern -> payments (crown jewel) + its data class pii.
	if !reflect.DeepEqual(linked[0].SystemRefs, []string{"payments"}) {
		t.Errorf("a1 systems = %v, want [payments]", linked[0].SystemRefs)
	}
	if !reflect.DeepEqual(linked[0].DataClassRefs, []string{"pii"}) {
		t.Errorf("a1 data classes = %v, want [pii]", linked[0].DataClassRefs)
	}
	// AES matched by bom-ref -> logging + ephemeral.
	if !reflect.DeepEqual(linked[1].SystemRefs, []string{"logging"}) {
		t.Errorf("a2 systems = %v, want [logging]", linked[1].SystemRefs)
	}
	// ML-KEM matched nothing.
	if len(linked[2].SystemRefs) != 0 {
		t.Errorf("a3 should match no system, got %v", linked[2].SystemRefs)
	}

	// Inputs must not be mutated.
	if assets[0].SystemRefs != nil {
		t.Error("Link mutated its input slice")
	}
}

func TestLink_NilContextIsNoop(t *testing.T) {
	assets := []model.Asset{{ID: "a1", Name: "RSA"}}
	out, err := Link(assets, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || len(out[0].SystemRefs) != 0 {
		t.Error("nil context should leave assets unchanged")
	}
}

func FuzzParseContext(f *testing.F) {
	for _, s := range []string{
		"schema_version: 1\nglobal_migration_time_years: 5\ncrqc_scenarios: [{name: a, years_until: 10}]\n",
		"not: valid: yaml: at: all",
		"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic; errors are fine.
		if c, err := parse(data); err == nil && c != nil {
			_ = checkCompleteness(c)
			_, _ = Link([]model.Asset{{ID: "x", Name: "RSA"}}, c)
		}
	})
}
