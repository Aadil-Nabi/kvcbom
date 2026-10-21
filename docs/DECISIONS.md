# Architecture Decision Records — kvcbom

Short ADR style: Context → Decision → Consequences. Newest first.
Status: `accepted` | `proposed` | `superseded`.

---

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
- **Status:** proposed (confirm at M2)
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
- **Status:** accepted (quality re-check at M6)
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
