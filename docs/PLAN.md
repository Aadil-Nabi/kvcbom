# kvcbom — Build Plan (for approval)

> Per SPEC §11.1. **No engine code has been written yet** beyond `go mod init` and a
> dependency probe. This document is for your sign-off before Milestone 1.

---

## 0. Key finding — `cyclonedx-go` supports 1.6 crypto properties ✅

Probed `github.com/CycloneDX/cyclonedx-go@v0.12.0` directly in the module cache:

- `SpecVersion1_6` exists; the library round-trips 1.6 **and** 1.7.
- `CryptoProperties` carries `AssetType` (`algorithm | certificate | protocol |
  related-crypto-material`), `OID`, and the four sub-property blocks
  (`AlgorithmProperties`, `ProtocolProperties`, `CertificateProperties`,
  `RelatedCryptoMaterialProperties`), including `ParameterSetIdentifier`, `Primitive`,
  `Mode`, `CryptoFunctions`, `EllipticCurve`, cipher suites, and `KeyLength`.
- Parses both JSON and XML.

**Decision:** use `cyclonedx-go` for ingest. We do **not** need a custom parser. We will
still run **JSON-Schema validation** against the official CycloneDX 1.6 schema separately
(the library parses leniently; `validate` must be strict), and keep a thin anti-corruption
layer so the rest of the engine never imports `cyclonedx-go` types directly.

## 1. Package structure (SPEC §10)

```
cmd/kvcbom/                 # cobra CLI — thin; parses flags, calls pkg/
pkg/
  model/                    # normalised domain model (no third-party types leak in)
  ingest/
    cbom/                   # cyclonedx-go → model (anti-corruption layer)
    register/               # xlsx/csv → model, via a YAML column mapping
    context/                # context YAML → model, JSON-Schema validated
  merge/                    # identity, dedup, evidence-merge, merge-decision log
  rulepack/                 # load/validate packs; classification table + rules
  classify/                 # algorithm → quantum_status via the pack table
  score/                    # quantum vuln + Mosca scenarios + criticality + evidence
  framework/                # findings → framework controls (placeholder-aware)
  report/                   # canonical Report assembly + Renderer interface
    render/json             # canonical JSON (source of truth) + schema
    render/html             # single self-contained HTML (html/template)
    render/md               # Markdown
    render/pdf              # Renderer impls: puregо (default) + chromium (optional)
  diff/                     # report-vs-report comparison
internal/
  config/                   # flags > env(KVCBOM_*) > file > defaults
  safety/                   # size limits, zip-bomb guard, path-traversal guard, XXE-off
  hashid/                   # SHA-256 of inputs/packs; stable asset identity hashing
  version/                  # ldflags: version, commit, date
  cli/                      # shared cobra plumbing, exit-code mapping, logging
rulepacks/                  # embedded YAML packs (baseline-pqc, nist-ir-8547, cnsa-2.0, csa-qri-sg)
templates/                  # embedded html/md templates
schemas/                    # embedded JSON Schemas: cyclonedx-1.6, context, rulepack, output
testdata/                   # hand-written + sample CBOMs, registers, contexts, goldens
docs/                       # PLAN, DECISIONS, USAGE, RULEPACKS, SCORING, CONTEXT
```

**Reuse rule:** `pkg/` is the product; `cmd/` only wires flags → library calls. A future
web service imports `pkg/report`, `pkg/score`, etc., unchanged (SPEC §3.6).

## 2. Key interfaces

```go
// ingest
type Ingester interface { Ingest(ctx, src Source) (*model.Batch, error) } // cbom/register/context

// rulepack
type Pack interface {
    Meta() PackMeta
    Classify(a model.Asset) (classify.Result, bool) // algorithm → quantum_status (+source)
    Rules() []Rule                                   // declarative, expr-lang conditions
    FrameworkMap() []Mapping
    Remediation(findingType string) (Remediation, bool)
    Validate() []PackIssue                            // missing-source = error; TODO = warn
}

// classify / score / rules operate on the model, produce Findings + RiskScore
type RuleEngine interface { Eval(assets []model.Asset, p Pack) []model.Finding }
type Scorer     interface { Score(a model.Asset, ctx *model.Context, p Pack) model.RiskScore }

// output — every format renders from the one canonical Report
type Renderer interface { Render(r *model.Report, w io.Writer) error }      // json/html/md
type PDFRenderer interface { Renderer; Name() string; Available() (bool, string) } // purego|chromium
```

All deterministic: no `time.Now()` inside the engine — the run timestamp is injected
(`--timestamp` / `SOURCE_DATE_EPOCH`), and every collection is sorted before emit.

## 3. Data model (SPEC §6) — core types

```go
type Asset struct {
    ID            string            // deterministic: hash(family|params|impl|location…)
    Type          AssetType         // algorithm|certificate|protocol|related-material
    Name          string
    AlgoFamily    string            // RSA, ECDSA, AES, SHA2, ML-KEM…
    ParamSet      string            // e.g. "rsa-2048", "P-256", "ML-KEM-768"
    KeySizeBits   *int
    Mode          string            // GCM, CBC…
    Primitive     string            // pke, signature, kem, hash, mac…
    OID           string
    Functions     []string          // sign, verify, encapsulate…
    Implementation string           // library/impl if known
    Locations     []string          // sorted
    SystemRefs    []string          // linked systems
    DataClassRefs []string          // linked data classes
    Evidence      []Evidence        // merged, sorted
}

type Evidence struct {
    SourceType  SourceType // scanner-cbom | manual-register | context
    SourceFile  string
    BOMRef      string
    Confidence  ConfLevel  // C1 weakest … C4 strongest (verified live config)
}

type Finding struct {
    RuleID       string
    Severity     Severity
    AssetID      string
    Title, Explanation string
    RemediationRef string
    EvidenceRefs []string
    Framework    []FrameworkRef // mapped controls (may carry TODO(source) flag)
}

type RiskScore struct {
    QuantumVulnerability float64 // from classification
    MoscaExposure        map[string]MoscaResult // per CRQC scenario
    Criticality          float64
    EvidenceAdjustment   float64 // affects certainty, NOT severity
    Final                float64
    Weights              Weights // echoed from the pack, shown in appendix
}

type MoscaResult struct { X, Y, Z float64; Exposed bool; HNDL bool; Scenario string }
```

`Context` holds `Systems[]`, `DataClasses[]` (with `ConfidentialityLifetimeYears`),
`MigrationTimeYears` (per-system + global default), `CRQCScenarios` (optimistic/central/
pessimistic — never a single hardcoded "fact"), link rules, and assessment metadata.

## 4. Dependencies (SPEC §10 — each justified; full ADRs in DECISIONS.md)

| Dependency | Why | Maintained? |
|---|---|---|
| `github.com/CycloneDX/cyclonedx-go` v0.12.0 | CBOM parse; 1.6 crypto verified | yes (OWASP/CycloneDX) |
| `github.com/spf13/cobra` | CLI (spec-mandated) | yes |
| `github.com/xuri/excelize/v2` | XLSX register (spec-mandated) | yes |
| `github.com/santhosh-tekuri/jsonschema/v6` | JSON-Schema validation (CBOM/context/pack/output), **offline** | yes |
| `github.com/goccy/go-yaml` | YAML (packs/context/mapping) — **chosen over archived `gopkg.in/yaml.v3`** | yes |
| `github.com/expr-lang/expr` | safe, sandboxed rule conditions — no arbitrary code exec | yes |
| `github.com/johnfercher/maroto/v2` | **pure-Go PDF** default (keeps single binary) | yes |
| config layering | **manual** (flags→env→file→defaults) using stdlib; add `koanf` only if it gets messy | n/a |

Deliberately avoided: `gopkg.in/yaml.v3` (archived), `jung-kurt/gofpdf` (archived),
`unidoc/unipdf` (commercial), `viper` (heavy), `chromedp` (pulls a large tree — see PDF).
Golden tests use stdlib + an `-update` flag (no `goldie` dependency).

## 5. PDF approach — recommendation (SPEC §9, §11.1)

Two engines behind the `PDFRenderer` interface; **default pure-Go**:

1. **`puregо` (default) — `maroto/v2`.** Renders the report straight from the canonical
   model: cover, tables, per-system/framework sections. *Pros:* single static binary,
   air-gap-safe, deterministic, no external process. *Cons:* we maintain layout in Go
   (can't reuse the HTML/CSS); styling is plainer. Acceptable for a professional,
   black-and-white, executive-readable report — which is exactly what SPEC §9 asks for.
2. **`chromium` (optional, opt-in `--pdf-engine chromium`) — local Chromium via `os/exec`.**
   Prints the **self-contained HTML** we already generate (`chrome --headless=new
   --print-to-pdf`), so layout = one source of truth and fidelity is pixel-perfect.
   *Pros:* best looking, reuses HTML. *Cons:* requires Chromium present (not air-gap-
   guaranteed), rendering not byte-deterministic. **We detect it and fail with a clear
   message when absent** (SPEC §9 explicitly permits this). Using `os/exec` instead of
   `chromedp` keeps the default binary lean — no heavy dependency for an optional feature.

**Recommendation:** ship **both**, default `puregо`. Teams that want a polished
customer-facing PDF and have Chromium opt into `--pdf-engine chromium`; locked-down/air-
gapped users get a fully offline PDF from the pure-Go engine. If, during M6, the pure-Go
output quality is unacceptable for customer sharing, I'll flag it and we decide whether to
invest more in the maroto layout or make Chromium the recommended path for shareable PDFs.

## 6. Milestones (SPEC §11.2) — deliverables + exit criteria

- **M1 — Model + CBOM ingest + `validate`.** `pkg/model`, `pkg/ingest/cbom` (JSON+XML via
  cyclonedx-go → model), embedded CycloneDX 1.6 schema + completeness checks, `validate`
  command, `internal/safety` (size/XXE/path guards). *Exit:* unit tests >80% on these pkgs,
  fuzz tests for CBOM JSON/XML, lint clean.
- **M2 — Rule packs + classification.** pack schema + loader + `Validate` (missing-source =
  error, TODO = warn), `baseline-pqc` pack (only certain facts, every entry source-URL'd),
  `classify`, `rulepacks list|show|validate`. *Exit:* table-driven classification tests,
  pack-validation tests.
- **M3 — Context + register + merge + scoring.** context YAML + JSON Schema, register
  (xlsx/csv + mapping), `merge` (identity/dedup/evidence-merge + decision log), `score`
  (quantum vuln + Mosca per scenario + criticality + evidence adjustment). *Exit:* Mosca
  boundary tests, merge determinism tests.
- **M4 — Outputs.** canonical JSON + output JSON Schema, HTML (self-contained,
  `html/template`), Markdown. *Exit:* golden tests (`-update`), determinism test (two runs =
  identical bytes).
- **M5 — `diff` + policy thresholds.** report-vs-report diff, `--fail-on` → exit code 3.
  *Exit:* diff tests, exit-code tests.
- **M6 — PDF + placeholder packs + CI + release + docs.** both PDF engines, `nist-ir-8547`/
  `cnsa-2.0`/`csa-qri-sg` structure-only packs (TODO(source) + draft), golangci-lint config,
  GitHub Actions (lint/test/race/govulncheck/cross-compile), GoReleaser (reproducible +
  cosign + tool SBOM), full `docs/`. *Exit:* all gates green; cross-compile matrix builds.

## 7. Open questions for you before M1

1. ~~**Module path**~~ — **resolved:** `github.com/Aadil-Nabi/kvcbom` — personal account,
   kept separate from Kvelden/Enclave (ADR-0006).
2. **Tool name / brand** — "kvcbom" everywhere, or a product display name on the report cover?
3. **PDF** — agree with "pure-Go default + optional Chromium"? (This is the one real design
   fork; everything else follows the spec.)
4. **Config layering** — manual stdlib is fine, or do you want `koanf` from the start?
5. **Sample CBOMs** — OK to vendor a couple of public CycloneDX CBOM samples (e.g. PQCA
   CBOMkit) into `testdata/` with source+licence recorded (SPEC §10), air-gap unaffected?

On approval I'll start **M1** and report back at each milestone per the spec.
