# Architecture Decision Records — kvcbom

Short ADR style: Context → Decision → Consequences. Newest first.
Status: `accepted` | `proposed` | `superseded`.

---

## ADR-0017 — Multi-framework reporting via classifier + regulator overlays
- **Status:** accepted
- **Context:** customers need the report mapped to their national regulator (CSA SG, ENISA, BSI,
  NCSC…), and often to more than one body at once. The classification (what is quantum-broken)
  is universal NIST-grounded fact; only the control *citation* differs per regulator. The M2
  framework packs bundled their own (compact, inferior) classification, duplicating logic.
- **Decision:** split packs into two kinds. A **classifier** (`baseline-pqc`) owns the
  classification table + rules and emits a **canonical finding-type vocabulary**
  (`quantum-vulnerable-key-establishment`, `-signature`, `-asymmetric`, `classically-broken-primitive`,
  `symmetric-strength-reduced`, `unclassified-crypto-asset`, `quantum-resistant-in-use`). A
  **framework overlay** carries no classifications — only `framework.mappings` keyed by that
  vocabulary. `report --rulepack <classifier> --framework <overlay>…` applies one classification
  and N regulator views; `Report.Frameworks` is a list, rendered as multiple sections (HTML/MD/PDF).
  The CLI guards against using an overlay as the classifier (clear error). The three M2 framework
  packs were converted to overlays; `enisa-eu` and `uk-ncsc` overlays were scaffolded. All
  control text stays `TODO(source):` and the report's warnings now flag unverified **overlay**
  content, not just the classifier's (so a draft regulator mapping can't be mistaken for a
  verified compliance claim). Per-regulator control text must be filled and verified by a human
  from primary documents — never fabricated.
- **Consequences:** one classification source of truth; adding a regulator is a pure content
  pack. Overlays are not standalone classifiers by design. (Surfaced and fixed here: fpdf emitted
  the font dictionary in map order — `SetCatalogSort(true)` restores byte-reproducible PDFs.)

## ADR-0016 — Scanner-agnostic ingest: version-selected schema (1.6 + 1.7), configurable property mapping, family-aware classification
- **Status:** accepted
- **Context:** the tool must accept CBOMs from any vendor (Keyfactor AgileSec, QuSecure, etc.)
  and support CycloneDX 1.7, which many tools now emit. Three gaps: (a) we only strict-validated
  1.6; (b) 1.7 populates `algorithmProperties.algorithmFamily` which our classifier ignored;
  (c) vendors record the algorithm under different property keys.
- **Decision:**
  - **Version-selected schema.** Embed the official 1.7 schema (plus its new
    `cryptography-defs.schema.json`) alongside 1.6; `ValidateSchema` reads the document's
    `specVersion` and validates against the matching compiled schema. Adding a future version is
    one entry in `bomSchemaIDs` + embedding its file — no logic change (open/closed). All
    schemas compile on one compiler so cross-refs (SPDX/JSF) resolve.
  - **Configurable property mapping.** A `Mapping` strategy object (`cbom.Mapping`, default +
    `--cbom-mapping` YAML) lists the property keys whose value is the algorithm, matched exactly
    or as a `*:suffix` wildcard. The ingester delegates "which property is the algorithm" to it,
    so a new vendor convention is a config change. `readProperties` now only reads/sorts
    (format-level); interpretation lives in the mapping (SRP).
  - **Family-aware classification.** Classification name-patterns now match the asset Name *or*
    AlgorithmFamily, so a 1.7 CBOM that names only the family still classifies — no pack changes.
- **Consequences:** standards-compliant vendor CBOMs (richer than the nmap sample) classify more
  cleanly; 1.7 files validate without the tolerance warning; the 1.7 schema is strict (e.g.
  namespaced curves like `nist/P-256`). SOLID review done alongside: `model` stays dependency-free,
  ingest remains the sole anti-corruption layer for cyclonedx-go, packs stay the open/closed
  extension point, interfaces only where multiple impls exist.

## ADR-0015 — Ingest reads CycloneDX component `properties`; adopts an algorithm-bearing property as the asset identity
- **Status:** accepted
- **Context:** real scanner CBOMs (validated against a 403 KB nmap-sourced sample) name each
  crypto-asset component by its **endpoint/location** (e.g. `172.31.100.107:22`) and leave the
  standard `name`/`cryptoProperties`/`oid` empty, recording the actual algorithm in the
  CycloneDX `properties` extension array (e.g. `qs:algorithm = diffie-hellman-group18-sha512`).
  The ingester ignored `properties`, so every asset's identity was the endpoint and everything
  classified as `unknown` — the tool was useless on this (common) shape of real data.
- **Decision:** the CBOM ingester now copies component `properties` onto the asset
  (`Asset.Properties`, sorted, for traceability) and, when a property's key is `algorithm` or
  ends with `:algorithm` (case-insensitive, vendor-neutral), **adopts its value as the asset's
  name/identity** and demotes the original component name to a location. Classification is
  unchanged — the existing name-pattern matchers now see the real algorithm string. This also
  fixes over-merging: distinct algorithms on one endpoint are now distinct assets.
- **Consequences:** the tool produces a real assessment of scanner output (on the sample, 129
  Shor-broken / 32 classically-broken / 23 Grover-weakened / 78 quantum-resistant with
  baseline-pqc; the ~90 remaining unknowns are legitimately protocol endpoints, key containers
  like JKS/PKCS#12, and non-crypto SSH tokens, not misses). We classify independently from the
  algorithm string and do **not** trust the scanner's own `qs:quantum_risk` label. Added
  ChaCha20/ChaCha20-Poly1305 to baseline-pqc (a real coverage gap surfaced here). Inferring a
  key-establishment primitive from the algorithm name (to enable HNDL without explicit
  `cryptoProperties`) is a possible future enhancement.

## ADR-0014 — `report` tolerates schema non-conformance (warns); `validate` stays strict
- **Status:** accepted
- **Context:** real-world "CycloneDX 1.6" CBOMs from scanners often carry a stray 1.7 field
  (e.g. `ellipticCurve` in `algorithmProperties`), which strict 1.6 validation rejects. The
  M4 `report` command treated any schema error as fatal (exit 2), so it could not assess an
  otherwise-usable real CBOM (cyclonedx-go parses these leniently).
- **Decision:** `report` records a schema non-conformance as a **warning** in the report's
  Warnings section and proceeds with the leniently-parsed assets; only a true decode failure
  (not JSON/XML, unreadable) is a hard exit-2 error. `validate` remains the strict schema gate
  (exit 2 on non-conformance), which is its purpose. Register header-mapping misses are folded
  into the same warning channel. Verified on a 403 KB real CBOM (80 assets) that carries 1.7
  fields: it now produces a full assessment with a visible caveat.
- **Consequences:** the tool is usable on real, near-1.6 CBOMs without pre-cleaning, while the
  report still honestly flags that an input did not fully conform. Strictness is a `validate`
  choice, not forced on every assessment.

## ADR-0013 — PDF: pure-Go via go-pdf/fpdf (default) + optional local Chromium (supersedes maroto in ADR-0003)
- **Status:** accepted (supersedes the maroto/v2 choice in ADR-0003)
- **Context:** ADR-0003 picked `maroto/v2` for the pure-Go PDF. In implementation its grid API
  proved heavy and higher-risk, and it wraps a gofpdf-style engine anyway.
- **Decision:** implement the `report.PDFRenderer` interface with two engines. **Default
  `purego`** uses the maintained `github.com/go-pdf/fpdf` (the active gofpdf fork) — a small
  imperative API, pure Go, single binary, air-gap safe; the creation date is stamped from the
  injected timestamp so output is byte-deterministic. **Optional `chromium`**
  (`--pdf-engine chromium`) prints the self-contained HTML via a locally discovered headless
  browser (Chrome/Chromium/Edge) run with networking disabled, failing with a clear message
  when none is present (SPEC §9 permits this). Core-font text is folded to Windows-1252 (the
  few non-representable glyphs like `→` are replaced).
- **Consequences:** offline users always get a PDF; teams wanting pixel-perfect output and with
  a browser opt into Chromium. go-pdf/fpdf avoids maroto's heavier dependency and API risk. The
  pure-Go layout is plainer than HTML — acceptable for the executive-readable B&W report §9 asks
  for; revisit only if customer feedback demands richer pure-Go layout.

## ADR-0012 — Diff over canonical JSON; two policy gates (report `--fail-on`, diff `--fail-on-regression`)
- **Status:** accepted
- **Context:** SPEC §4 needs `diff` to track progress between assessments; SPEC §8 needs policy
  thresholds returning exit code 3 for CI. The canonical JSON report (ADR-0011) is the contract.
- **Decision:** `pkg/diff.Compare(baseline, current *report.Report)` keys assets by their
  deterministic `Asset.ID` and findings by `ruleID\x1fassetID`, producing added/removed/changed
  assets and opened/resolved findings, all sorted. A change is a "regression" when the final
  score rose or HNDL was newly set. `json.Unmarshal` added to the json renderer parses canonical
  reports back and rejects an unknown `schema_version` so diff never compares incompatible docs.
  `diff` renders JSON or Markdown (stdout when no `--out`, files otherwise). Two independent
  gates both exit `3` (`cli.ExitPolicy`): `report --fail-on <severity>` (any finding at or above
  the threshold) and `diff --fail-on-regression` (any asset regression or new finding) — outputs
  are always written **before** the gate fails, so CI still gets the artifacts. Hardened
  `cli.CodeOf(nil)` to return `ExitOK` (was `ExitUsage`; `main` only called it on non-nil, but
  it was a footgun the CLI tests surfaced).
- **Consequences:** progress is machine-trackable and CI-gateable without extra state. Because
  diff keys on the identity hash, a changed identity field shows as remove+add (honest: it is a
  different asset), while same-identity score/status moves show as a change. HTML diff is not
  provided (diff is for CI/PRs — JSON and Markdown); it can be added later without API change.

## ADR-0011 — Canonical JSON Report is the single source of truth; renderers are pure consumers
- **Status:** accepted
- **Context:** SPEC §9 requires JSON (with its own published schema), HTML, and Markdown, with
  every format derived from one structure, `diff` consuming the JSON, and byte-identical output
  across runs. The report must also be reproducible (injected timestamp).
- **Decision:** `report.Report` (in `pkg/report`, `schema_version` independent of tool/pack
  versions) is the canonical structure; `report.Build` runs the pipeline
  (merge → link → classify → rules → score) and assembles it with everything pre-sorted and **no
  maps serialised**, so struct field order makes the JSON byte-stable. `pkg/report/render/{json,
  html,md}` each implement a `Renderer` and only read a `*Report` — they never re-compute. JSON
  disables HTML escaping and validates against embedded `schemas/output/report-1.schema.json`.
  HTML uses `html/template` (contextual auto-escaping; no `template.HTML` on input-derived data),
  is fully self-contained (inline CSS, no external fonts/scripts/CDN), and print-friendly in B&W.
  The run timestamp is injected via `--timestamp` / `SOURCE_DATE_EPOCH` / now, normalised to UTC.
  `report` refuses a non-empty `--out` unless `--force`, and writes only within `--out`.
- **Consequences:** golden tests (`-update`) plus a determinism test (two builds → identical
  bytes) pin the output; a schema check guards the JSON contract. The rule *evaluator* from M3
  and the scorer are first wired end-to-end here. PDF (M6) becomes a fourth renderer over the
  same Report. `diff` (M5) will parse the canonical JSON back.

## ADR-0010 — Shared asset identity in `model`; register via YAML column mapping; single merge pass
- **Status:** accepted
- **Context:** the same asset appears across multiple CBOMs and the manual register and must
  collapse to one record (SPEC §6). CBOM ingest already computed a deterministic identity, but
  it lived unexported in `pkg/ingest/cbom`, so the register and merge could not agree with it.
- **Decision:** promote the identity rule to `model.AssetIdentity(Asset)` (hash of type, family,
  parameter set, mode, primitive, curve, OID, key size, implementation, sorted locations; Name
  folded in only when family+paramset+OID are all empty). CBOM and register ingest both call it.
  `pkg/merge` groups by that ID, merges evidence lists (deduped, sorted), unions locations and
  links, picks a deterministic base record (most evidence, then lowest first bom-ref), and emits
  a decision only when a real collapse happened. The register reads XLSX (excelize) and CSV via a
  YAML **column mapping** (default embedded, overridable) so differently-labelled sheets work
  without code changes; header-based mapping only for v1 (index-based deferred). Register entries
  default to confidence **C1** (asserted) unless a row says otherwise.
- **Consequences:** one identity definition, used everywhere; merge is order-independent and
  byte-deterministic (tested). `excelize` is a heavier dependency but is spec-mandated for XLSX;
  register input is size/row-capped as untrusted input.

## ADR-0009 — Risk scoring: weighted four-component model; evidence affects score, low confidence flagged
- **Status:** accepted
- **Context:** SPEC §6/§8 require a broken-out risk score (quantum vulnerability, Mosca exposure,
  criticality, evidence confidence) with pack-configurable weights, plus "evidence adjusts
  certainty, not severity" and findings listed as "requires verification" when weak.
- **Decision:** `Final = (wQ·Q + wM·Mosca + wC·Crit + wE·Conf) / Σw`, all components in [0,1],
  echoed in the score so nothing is opaque. Q by status (shor/classically-broken=1.0,
  grover=0.5, unknown=0.3, resistant=0.0). Mosca per CRQC scenario: exposed when X+Y>Z **and**
  the asset is quantum-vulnerable; HNDL when exposed, Shor-broken, and confidentiality-protecting;
  computed only when a data class is linked (else noted). Criticality from linked systems (crown
  jewel ⇒ critical), defaulting to medium with a note when no system is linked. Evidence
  confidence (C1=0.25…C4=1.0) is a small-weight component **and** drives a `RequiresVerification`
  flag on findings when ≤ C2 — so weak evidence is surfaced, not silently downgraded.
- **Consequences:** scores are explainable and reproducible; missing context degrades gracefully
  with recorded notes rather than silently zeroing risk. CRQC years are always user-supplied
  scenarios — never a hardcoded "fact" (SPEC §5.3). The rule evaluator (`pkg/rules`, deferred from
  M2) classifies each asset, builds the `RuleInput`, and emits findings with evidence refs,
  framework refs, and the verification flag.

## ADR-0008 — Classification matching: declarative multi-dimension matcher with specificity ranking
- **Status:** accepted
- **Context:** CycloneDX 1.6 carries no `algorithmFamily` field (M1 finding), so classification
  must work from the asset's own self-description: component name, OID, parameter set, key size,
  primitive, and curve. A single key (e.g. "family + parameter set") is insufficient and would
  force kvcbom to assert a large table of OIDs it cannot all verify.
- **Decision:** each classification entry carries a `match` with optional dimensions (`oids`,
  `param_sets`, `name_patterns` [RE2 regex], `primitives`, `curves`, `key_bits`). An entry
  matches when **every specified** dimension matches (AND); an entry with no criteria never
  matches. Among matching entries the **most specific** wins, by fixed per-dimension weights
  (oid ≫ key_bits > param_set > curve > name > primitive); ties break to the **earliest entry
  in pack order**. Name patterns are the primary backbone (robust, verifiable, no OID table to
  assert); OIDs are an optional high-confidence fast path. The result records the matched entry,
  the deciding dimensions, the source reference, and the pack id+version for report traceability.
- **Consequences:** deterministic and explainable classification without inventing standards
  content. Pack authors order post-quantum entries first so order-based tie-breaks resolve
  substring collisions correctly (e.g. "ML-DSA" contains "DSA"); this ordering convention is the
  one subtlety and is covered by tests. RE2 has no look-behind, which is why ordering — not
  negative patterns — disambiguates those collisions.

## ADR-0007 — Rule-pack format: single-file YAML + JSON Schema; concrete `Pack`; expr compile-check at validate
- **Status:** accepted
- **Context:** SPEC §7 requires versioned YAML packs with a JSON Schema, embedded and
  disk-overridable, carrying a classification table, rules, framework mappings, remediation, and
  sources; `rulepacks validate` must error on a missing source reference and warn on remaining
  `TODO(source):` markers.
- **Decision:** one pack = one YAML file (`rulepacks/<id>.yaml`), embedded via a `rulepacks`
  package (same pattern as `schemas`) because `//go:embed` cannot reach a sibling directory.
  Validation is two-stage: **structural** against an embedded JSON Schema
  (`schemas/rulepack/rulepack-1.schema.json`, `additionalProperties:false`) at load time, then
  **semantic** in `Pack.Validate()` — dangling source/remediation references and duplicate ids
  are errors; TODO markers, empty-match entries, and draft/vendor status are warnings. Rule
  `when` conditions are compiled with `expr-lang/expr` against a fixed `RuleInput` env during
  validation, so pack typos are caught early. `Pack` is a **concrete struct**, not the interface
  sketched in PLAN §2 — there is one implementation, so an interface would be premature.
- **Consequences:** packs fail fast and legibly. The rule *evaluator* (producing findings from
  `when` + classification) is deferred to M3 with scoring, where it belongs; M2 only compiles
  expressions. **Directory-of-YAML packs are deferred** (single-file satisfies the core need);
  the loader API (`Load`/`LoadPath`) will not change when added. YAML→JSON normalisation feeds
  the schema validator (`goccy/go-yaml` → `encoding/json` → santhosh-tekuri).

## ADR-0006 — Personal ownership; module path `github.com/Aadil-Nabi/kvcbom`
- **Status:** accepted
- **Context:** `kvcbom` is a standalone PQC/CBOM assessment tool, separate from the Kvelden
  (Enclave) product. Clean IP/ownership separation is preferred, with freedom to open-source
  or commercialise it independently later.
- **Decision:** host under the owner's **personal** GitHub account; module path
  `github.com/Aadil-Nabi/kvcbom`. Not part of the Kvelden org/repos.
- **Consequences:** no entanglement with Kvelden licensing/org; renaming is cheap now (nothing
  imports the path yet) and costly after external consumers exist — so it is fixed at M0.

## ADR-0005 — Rule conditions via `expr-lang/expr` (sandboxed), not custom DSL or Go plugins
- **Status:** accepted (confirmed at M2: packs compile `when` against a fixed `RuleInput` env)
- **Context:** SPEC §7 requires declarative rules with "no arbitrary code execution".
- **Decision:** evaluate rule conditions with `github.com/expr-lang/expr` against a read-only
  view of the asset model. No file/network/OS access is exposed to expressions.
- **Consequences:** expressive, safe rules in YAML; one dependency; must pin the exposed
  environment so packs can't reach beyond the asset fields we allow.

## ADR-0004 — JSON-Schema validation via `santhosh-tekuri/jsonschema/v6`
- **Status:** accepted
- **Context:** `validate` must strictly schema-check CBOMs against CycloneDX 1.6, and we also
  validate the context file, rule packs, and our own output — all **offline**.
- **Decision:** use `github.com/santhosh-tekuri/jsonschema/v6` (draft 2020-12, pure Go, no
  network). Embed the CycloneDX 1.6 JSON schema **and its referenced schemas** (spdx, jsf) so
  `$ref` resolution works air-gapped.
- **Consequences:** one well-maintained dependency; we must vendor the referenced schemas and
  record their source/licence under `schemas/`.

## ADR-0003 — PDF: pure-Go (`maroto/v2`) default + optional local-Chromium engine
- **Status:** superseded by ADR-0013 (the pure-Go engine is `go-pdf/fpdf`, not maroto/v2; the
  two-engine design and Chromium fallback stand)
- **Context:** SPEC §9 wants shareable PDFs but §3 demands a single static, air-gap-safe
  binary. These pull in opposite directions.
- **Decision:** a `PDFRenderer` interface with two engines. **Default `purego`** (`maroto/v2`)
  renders from the canonical model — fully offline, deterministic, single binary. **Optional
  `chromium`** prints the self-contained HTML via a locally installed browser using `os/exec`
  (`--headless=new --print-to-pdf`); detect it and fail clearly when absent (§9 permits this).
  `os/exec` avoids the heavy `chromedp` dependency for an optional feature.
- **Consequences:** offline users always get a PDF; teams wanting pixel-perfect customer PDFs
  opt into Chromium. Layout exists twice (Go for purego, HTML for chromium) — acceptable; the
  canonical model is the single source of data. Re-evaluate purego quality at M6.

## ADR-0002 — YAML via `goccy/go-yaml`, not `gopkg.in/yaml.v3`
- **Status:** accepted
- **Context:** SPEC §10 warns to check for archived libraries. `gopkg.in/yaml.v3` is in
  archived/maintenance status.
- **Decision:** use `github.com/goccy/go-yaml` (actively maintained, better error locations,
  pure Go) for rule packs, context, and the register column-mapping file.
- **Consequences:** one actively-maintained YAML dependency; slightly different API than
  yaml.v3; richer parse errors help users fix malformed packs/context.

## ADR-0001 — Use `cyclonedx-go` for CBOM ingest (1.6 crypto verified)
- **Status:** accepted
- **Context:** SPEC §5.1 asks whether `cyclonedx-go` fully supports 1.6 `cryptoProperties`,
  else write a focused parser.
- **Decision:** verified `v0.12.0` exposes the full crypto surface (`CryptoProperties` with
  `AssetType`/`OID`/algorithm/protocol/certificate/related-material sub-blocks,
  `ParameterSetIdentifier`, `Primitive`, `Mode`, `CryptoFunctions`, `KeyLength`; JSON+XML;
  `SpecVersion1_6`). **Use the library.** Wrap it in an anti-corruption layer (`pkg/ingest/cbom`)
  so no other package imports cyclonedx-go types. Run strict JSON-Schema validation separately
  (the library parses leniently).
- **Consequences:** no custom parser to maintain; we inherit the library's parsing. The ACL
  isolates us from upstream type churn (they're already moving toward 1.7 structured forms).
