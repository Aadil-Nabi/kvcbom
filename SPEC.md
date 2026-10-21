# Build Spec: `kvcbom` — CBOM Risk Assessment & Report Generator (Go)

You are building a production-grade, enterprise-ready command-line tool in Go. Read this whole document before writing any code. Follow the "How to work" section strictly.

---

## 1. What the tool does

`kvcbom` takes one or more **CycloneDX 1.6 Cryptographic Bills of Materials (CBOMs)**, optional supporting inputs, and a selected **rule pack**, and produces a **post-quantum cryptographic risk assessment report**.

Pipeline:

```
ingest → validate → normalise & merge → classify → score → map to framework → render report
```

Primary users: security consultants and internal security teams running cryptographic readiness assessments, often on locked-down laptops inside customer networks with no internet access.

Report readers: CISOs, auditors, regulators, and engineering leads. The report must be credible to all of them.

## 2. Non-goals (do not build these)

- No cryptographic discovery or scanning. We consume CBOMs produced by other tools.
- No network calls of any kind at runtime. No telemetry, no update checks, no remote rule fetching.
- No web UI, no database server, no SaaS components.
- No live threat detection. "Threat" here means threat modelling and risk scoring of inventoried assets.

## 3. Hard constraints

1. **Single static binary** for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64. `CGO_ENABLED=0`. No runtime dependencies.
2. **Air-gap safe.** Works fully offline. Rule packs and report templates are embedded via `embed`, and can be overridden from disk.
3. **Deterministic output.** Same inputs + same rule pack version = byte-identical JSON output. Sort everything. No map iteration order leaking into output. Timestamps only where explicitly recorded, and overridable with `--timestamp` / `SOURCE_DATE_EPOCH` for reproducible runs.
4. **Traceability.** Every finding must trace back to: the input file, the component `bom-ref`, the rule ID, and the rule pack version that produced it. Every report records SHA-256 hashes of all inputs and the rule pack.
5. **Do not invent standards content.** Never fabricate control IDs, objective names, deprecation dates, or requirement text from CSA, MAS, NIST, CNSA, or any other framework. Where real content is needed, create the structure with clearly marked `TODO(source):` placeholders and a `source_url` field left for a human to fill and verify. Include only facts you are certain of (e.g. FIPS 203/204/205 algorithm names), and still attach a source URL to each.
6. **Library = the product, CLI = thin wrapper.** All logic lives in importable packages under `pkg/` (or `internal/` where it must not be public). The CLI only parses flags and calls the library. A future web service must be able to reuse the engine without changes.

## 4. CLI surface

Use `cobra`. Commands:

```
kvcbom validate  --cbom <file>... [--context <file>] [--strict]
kvcbom report    --cbom <file>... [--register <xlsx|csv>] [--context <file>]
                 --rulepack <id|path> [--format html,json,md,pdf] --out <dir>
                 [--title <str>] [--org <str>] [--timestamp <rfc3339>]
kvcbom diff      --baseline <report.json> --current <report.json> [--format ...] --out <dir>
kvcbom rulepacks list
kvcbom rulepacks show <id>
kvcbom rulepacks validate <path>
kvcbom version
```

Behaviour:

- `validate`: schema-check each CBOM against CycloneDX 1.6, then a **completeness check** listing fields missing for good scoring (e.g. no key size, no mode, no data classification link). Output a human table to stderr and optional JSON with `--json`.
- `report`: full pipeline. Writes outputs into `--out`. Refuses to overwrite a non-empty directory unless `--force`.
- `diff`: compares two report JSON files and shows assets added, removed, and risk changes. This is how progress is tracked between assessments.
- Global flags: `--log-level`, `--log-format text|json`, `--no-color`, `--config <file>`.
- **Exit codes** (document them): `0` success, `1` usage error, `2` input validation failure, `3` policy threshold breached (see §8), `4` internal error.
- Config precedence: flags > env vars (`KVCBOM_*`) > config file > defaults.

## 5. Inputs

### 5.1 CBOM (required, one or more)
- CycloneDX 1.6, JSON and XML. Use `github.com/CycloneDX/cyclonedx-go` if it fully supports 1.6 `cryptoProperties`; verify this first and report back. If support is incomplete, write a focused parser for the crypto-asset subset and explain why.
- Handle `cryptographic-asset` components of all asset types: algorithm, certificate, protocol, related-crypto-material.
- Preserve `dependencies` relationships (e.g. protocol → cipher suite → algorithm, certificate → signature algorithm).

### 5.2 Manual register (optional)
- XLSX or CSV of assets gathered from interviews or manual review. Use `excelize` for XLSX.
- Column mapping defined in a YAML mapping file so different spreadsheet layouts can be supported without code changes. Ship one default mapping.
- Register rows become assets like any other, marked with their source.

### 5.3 Context file (optional, YAML)
Business context a CBOM cannot carry. Schema must include at least:
- Systems/applications, each with: id, name, owner, criticality, whether it is a crown-jewel system.
- Data classes, each with: id, name, **confidentiality lifetime in years** (how long the data must stay secret).
- **Estimated migration time in years**, per system or global default.
- **CRQC arrival assumption in years**, with a scenario range (e.g. optimistic / central / pessimistic) set by the user. Never hardcode a single value as fact.
- Mapping rules linking CBOM components to systems (by `bom-ref`, name pattern, or property).
- Assessment metadata: organisation, assessor, scope statement.

Publish a JSON Schema for this file and validate against it.

### 5.4 Input safety
Treat every input as untrusted:
- Size limits on all files (configurable, sensible defaults).
- XLSX zip-bomb protection and limits on rows/cells.
- No path traversal from any value in any input.
- XML parsing with no external entity resolution.
- All text rendered into HTML goes through `html/template` escaping. Never `template.HTML` on input-derived data.

## 6. Data model

Design a normalised internal model. At minimum:

- **Asset**: stable ID, type, name, algorithm family, parameter set / key size, mode, primitive, OID, crypto functions, library/implementation, location(s), linked system(s), linked data class(es).
- **Evidence**: one or more per asset. Each records source type (`scanner-cbom`, `manual-register`, `context`), source file, `bom-ref`, and **evidence confidence** on a C1–C4 scale where **C1 = weakest (asserted/verbal) and C4 = strongest (verified from live configuration)**. Scanner-derived evidence defaults to a configurable level; register rows carry their own level in a column.
- **Finding**: rule ID, severity, asset ID, explanation, remediation reference, evidence refs.
- **RiskScore**: components broken out (quantum vulnerability, Mosca exposure, criticality, evidence confidence adjustment) plus the final score. Never output an opaque number without its breakdown.

**Merging and deduplication:** the same asset will appear in multiple CBOMs and in the register. Define deterministic identity rules (e.g. algorithm + parameters + implementation + location), merge evidence lists rather than dropping duplicates, and record merge decisions so they appear in the report appendix.

## 7. Rule packs

Rule packs are versioned YAML (or a directory of YAML files) with a JSON Schema. Embedded defaults, overridable with `--rulepack ./path`.

Each pack contains:
- `id`, `version` (semver), `name`, `description`, `status` (`final` | `draft` | `vendor`), `sources` (list of `{title, url, status, retrieved_date}`).
- **Algorithm classification table:** for each algorithm/parameter set → `quantum_status` (`shor_broken` | `grover_weakened` | `quantum_resistant` | `classically_broken` | `unknown`), plus optional deprecation / disallowance dates, each with a source reference.
- **Rules:** declarative conditions over the asset model producing findings with severity. Use a small, safe expression approach (e.g. structured YAML conditions, or a sandboxed library like `expr-lang/expr`). No arbitrary code execution.
- **Framework mapping:** findings → framework controls/objectives, with control IDs and text left as `TODO(source):` placeholders unless certain.
- **Remediation guidance** keyed by finding type.

Ship these packs:
1. `baseline-pqc` — generic quantum-vulnerability classification using only well-established facts (RSA, ECC, DH, ECDH, DSA are Shor-broken; symmetric and hash sizes per Grover; ML-KEM / ML-DSA / SLH-DSA per FIPS 203/204/205 as quantum-resistant). Every entry has a source URL.
2. `nist-ir-8547` — structure only, with dates as `TODO(source):` placeholders and `status: draft` unless verified final.
3. `cnsa-2.0` — structure only, same treatment.
4. `csa-qri-sg` — structure only: objective/control slots as `TODO(source):` placeholders, to be filled by a human from the official CSA Singapore documents.

`kvcbom rulepacks validate` must fail any pack with a rule or classification entry missing a source reference, and **warn** on remaining `TODO(source):` markers. Reports generated with a pack containing TODOs must display a visible "unverified rule content" warning.

## 8. Scoring

- **Quantum vulnerability** from the classification table.
- **Mosca exposure:** for each asset linked to a data class and system, compute `X + Y > Z` where X = confidentiality lifetime, Y = migration time, Z = CRQC arrival assumption. Compute for each CRQC scenario. Flag harvest-now-decrypt-later exposure where key establishment protecting long-lived data is Shor-broken.
- **Criticality** from the context file.
- **Evidence confidence** adjusts certainty, not severity: show low-confidence findings clearly, and list them as "requires verification".
- Final score: documented, configurable weights in the rule pack. Output the formula and weights in the report appendix.
- **Policy thresholds** (`--fail-on critical|high|...`): exit code `3` when breached, for CI/CD use.

## 9. Outputs

Required in v1:
- **JSON** — the canonical, versioned, machine-readable result with its own published JSON Schema. Every other format is rendered from this. `diff` consumes it.
- **HTML** — single self-contained file (inline CSS, no external fonts or scripts, no CDN). Print-friendly. Plain, professional, black-and-white-friendly design. Readable by non-technical executives at the top, detailed below.
- **Markdown** — for pasting into wikis and tickets.

PDF:
- Implement behind a `Renderer` interface. Default to a pure-Go approach so the single-binary constraint holds. Evaluate options, recommend one, and explain trade-offs before implementing. If quality is poor, it is acceptable to ship PDF as an optional renderer that uses a locally installed Chromium when present, and fails with a clear message when not.

Report structure:
1. Cover: title, organisation, scope, date, tool version, rule pack id + version, input hashes.
2. Warnings: unverified rule content, low-confidence evidence share, incomplete CBOM fields.
3. Executive summary: plain English, one page. Headline risk counts, top 5 risks, HNDL exposure summary, Mosca outcome per scenario.
4. Inventory overview: counts by asset type, quantum status, system, evidence confidence.
5. Findings register: sortable table (HTML), grouped by severity.
6. Per-system view: assets, findings, Mosca result.
7. Framework mapping view.
8. Remediation roadmap: ordered by risk, separating quick wins from long migrations.
9. Appendix: methodology, scoring formula and weights, merge/dedup decisions, full source list with status (final / draft / vendor), input file hashes.

Write report text in plain English. No marketing language. Define every acronym on first use.

## 10. Engineering standards

- **Go version:** latest stable. Modules. Verify each third-party dependency is actively maintained before adopting it (check for archived repos, e.g. some YAML libraries). Keep dependencies minimal and justify each one in `docs/DECISIONS.md`.
- **Layout:** `cmd/kvcbom`, `pkg/...` for engine packages (ingest, model, merge, classify, score, rulepack, report), `internal/...` for private helpers, `rulepacks/`, `templates/`, `schemas/`, `testdata/`, `docs/`.
- **Errors:** wrap with context, typed sentinel errors where callers need to branch. No panics on user input.
- **Logging:** `log/slog`. Never log full input contents at info level.
- **Testing:**
  - Unit tests for every package; aim for >80% coverage on engine packages.
  - **Golden-file tests** for JSON, HTML, and Markdown output, with an `-update` flag.
  - **Fuzz tests** (`go test -fuzz`) for CBOM JSON/XML parsing, register parsing, and context parsing.
  - Table-driven tests for classification and Mosca maths, including boundary cases.
  - Determinism test: run the same report twice and assert identical JSON bytes.
  - Test fixtures: hand-written small CBOMs covering every asset type, plus real-world-shaped samples. If you use public sample CBOMs (e.g. from the PQCA CBOMkit project), record their source and licence in `testdata/README.md`.
- **Quality gates:** `golangci-lint` with a committed config, `go vet`, `staticcheck`, `govulncheck`. A `Makefile` with `build`, `test`, `lint`, `fuzz`, `release-snapshot`.
- **CI:** GitHub Actions running lint, test, race detector, govulncheck, and a cross-compile matrix.
- **Releases:** GoReleaser with reproducible builds (`-trimpath`, fixed `mod_timestamp`), checksums, a CycloneDX SBOM of the tool itself, and cosign signing configured (keyless or key-based, documented).
- **Versioning:** semver for the tool, the JSON output schema, and each rule pack independently. Embed version, commit, and build date via ldflags.
- **Docs:** `README.md` (install, quick start, examples), `docs/USAGE.md`, `docs/RULEPACKS.md` (how to write and verify a pack), `docs/SCORING.md`, `docs/CONTEXT.md`, `docs/DECISIONS.md`, `SECURITY.md`, `CHANGELOG.md`.
- **Licence:** leave a `LICENSE` placeholder; do not choose one.

## 11. How to work

1. **Plan first.** Before writing code, produce `docs/PLAN.md` containing: package structure, key interfaces, data model types, dependency choices with justification, the PDF approach recommendation, and milestone breakdown. Also report whether `cyclonedx-go` fully supports 1.6 crypto properties. **Stop and wait for my approval.**
2. **Build in milestones.** After each milestone: all tests pass, lint is clean, and you give me a short summary of what was built and anything you deferred. Suggested order:
   - M1: model, CBOM ingest (JSON + XML), `validate` command, schema + completeness checks, tests and fuzzing.
   - M2: rule pack format, schema, loader, `baseline-pqc` pack, classification engine, `rulepacks` commands.
   - M3: context file, register ingest, merge/dedup, scoring with Mosca scenarios.
   - M4: JSON output + schema, HTML and Markdown renderers, golden tests, determinism test.
   - M5: `diff` command, policy thresholds and exit codes.
   - M6: PDF renderer, placeholder framework packs, CI, GoReleaser, docs.
3. **Record decisions** in `docs/DECISIONS.md` as you go (short ADR style: context, decision, consequences).
4. **When unsure about a standard's content, leave a `TODO(source):` placeholder and tell me.** Do not guess. A wrong regulatory claim in a report is worse than a missing one.
5. Do not add features outside this spec without asking. If you think something is missing, propose it.
