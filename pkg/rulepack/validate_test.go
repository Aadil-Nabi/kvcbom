package rulepack

import (
	"strings"
	"testing"
)

const validPack = `
schema_version: 1
id: test-pack
version: 0.1.0
name: Test Pack
status: final
sources:
  - id: src1
    title: A source
    url: https://example.com/doc
    status: final
classifications:
  - id: c1
    quantum_status: shor_broken
    source: src1
    match:
      name_patterns: ["(?i)rsa"]
remediation:
  - id: fix1
    summary: Do the thing
    references: [src1]
rules:
  - id: R1
    title: Vulnerable
    severity: critical
    finding_type: vuln
    when: 'Status == "shor_broken"'
    remediation: fix1
`

func mustLoadBytes(t *testing.T, y string) *Pack {
	t.Helper()
	p, err := loadBytes([]byte(y))
	if err != nil {
		t.Fatalf("loadBytes: %v", err)
	}
	return p
}

func countErrors(issues []PackIssue) int {
	n := 0
	for _, i := range issues {
		if i.Level == LevelError {
			n++
		}
	}
	return n
}

func TestValidate_CleanPack(t *testing.T) {
	p := mustLoadBytes(t, validPack)
	if issues := p.Validate(); len(issues) != 0 {
		t.Fatalf("expected no issues, got %v", issues)
	}
}

func TestValidate_DanglingClassificationSource(t *testing.T) {
	y := strings.Replace(validPack, "source: src1", "source: ghost", 1)
	p := mustLoadBytes(t, y)
	issues := p.Validate()
	if countErrors(issues) == 0 {
		t.Fatalf("expected an error for a dangling classification source, got %v", issues)
	}
}

func TestValidate_DanglingRuleRemediation(t *testing.T) {
	y := strings.Replace(validPack, "remediation: fix1", "remediation: nope", 1)
	p := mustLoadBytes(t, y)
	if countErrors(p.Validate()) == 0 {
		t.Fatal("expected an error for a rule referencing an undefined remediation")
	}
}

func TestValidate_DanglingRemediationReference(t *testing.T) {
	y := strings.Replace(validPack, "references: [src1]", "references: [ghost]", 1)
	p := mustLoadBytes(t, y)
	if countErrors(p.Validate()) == 0 {
		t.Fatal("expected an error for a remediation referencing an undeclared source")
	}
}

func TestValidate_BadExpressionIsError(t *testing.T) {
	y := strings.Replace(validPack, `when: 'Status == "shor_broken"'`, `when: 'Status =='`, 1)
	p := mustLoadBytes(t, y)
	issues := p.Validate()
	if countErrors(issues) == 0 {
		t.Fatalf("expected a compile error for a malformed when-expression, got %v", issues)
	}
}

func TestValidate_TODOSourceWarns(t *testing.T) {
	y := strings.Replace(validPack, "url: https://example.com/doc", "url: \"TODO(source): find the URL\"", 1)
	p := mustLoadBytes(t, y)
	issues := p.Validate()
	if countErrors(issues) != 0 {
		t.Errorf("a TODO marker should warn, not error: %v", issues)
	}
	warned := false
	for _, i := range issues {
		if i.Level == LevelWarn {
			warned = true
		}
	}
	if !warned {
		t.Error("expected a warning for the TODO(source) marker")
	}
	if !p.HasUnverifiedContent() {
		t.Error("a pack with a TODO(source) marker must report unverified content")
	}
}

func TestValidate_DraftStatusIsUnverified(t *testing.T) {
	y := strings.Replace(validPack, "status: final", "status: draft", 1)
	p := mustLoadBytes(t, y)
	if !p.HasUnverifiedContent() {
		t.Error("a draft pack must report unverified content")
	}
}

func TestValidate_DuplicateClassificationID(t *testing.T) {
	// Insert a second classification with the same id, as a sibling in the list.
	dup := "      name_patterns: [\"(?i)rsa\"]\n" +
		"  - id: c1\n" +
		"    quantum_status: grover_weakened\n" +
		"    source: src1\n" +
		"    match:\n" +
		"      name_patterns: [\"(?i)aes\"]"
	y := strings.Replace(validPack, "      name_patterns: [\"(?i)rsa\"]", dup, 1)
	p := mustLoadBytes(t, y)
	if countErrors(p.Validate()) == 0 {
		t.Fatal("expected an error for a duplicate classification id")
	}
}

func TestValidate_EmptyMatchWarns(t *testing.T) {
	y := strings.Replace(validPack,
		"    match:\n      name_patterns: [\"(?i)rsa\"]",
		"    match: {}", 1)
	p := mustLoadBytes(t, y)
	issues := p.Validate()
	if countErrors(issues) != 0 {
		t.Errorf("an empty match should warn, not error: %v", issues)
	}
	found := false
	for _, i := range issues {
		if i.Level == LevelWarn && strings.Contains(i.Message, "match") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning about empty match criteria, got %v", issues)
	}
}

func TestLoad_BadRegexFails(t *testing.T) {
	y := strings.Replace(validPack, `["(?i)rsa"]`, `["("]`, 1)
	if _, err := loadBytes([]byte(y)); err == nil {
		t.Fatal("expected loadBytes to fail on an invalid regex")
	}
}

func TestLoad_SchemaViolationFails(t *testing.T) {
	// quantum_status not in the enum.
	y := strings.Replace(validPack, "quantum_status: shor_broken", "quantum_status: banana", 1)
	if _, err := loadBytes([]byte(y)); err == nil {
		t.Fatal("expected a schema violation for an invalid quantum_status")
	}
}

func TestLoad_UnknownTopLevelFieldFails(t *testing.T) {
	y := validPack + "\nbogus_field: 1\n"
	if _, err := loadBytes([]byte(y)); err == nil {
		t.Fatal("expected a schema violation for an unknown top-level field")
	}
}
