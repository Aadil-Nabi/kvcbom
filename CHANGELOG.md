# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- CBOM ingest for CycloneDX 1.6 (JSON and XML) with strict JSON-Schema validation and
  completeness checks; `validate` command.
- Rule-pack format (versioned YAML + JSON Schema), loader, and semantic validation; `rulepacks
  list|show|validate`. Deterministic, source-cited algorithm classification engine.
- `baseline-pqc` rule pack built only from established, source-cited facts.
- Structure-only framework packs `nist-ir-8547`, `cnsa-2.0`, and `csa-qri-sg` with control text
  as `TODO(source):` placeholders.
- Optional manual register ingest (XLSX/CSV) via a YAML column mapping; assessment context file
  (systems, data classes, migration time, CRQC scenarios, link rules) with JSON Schema.
- Deterministic merge/deduplication with a decision log; risk scoring (quantum vulnerability,
  Mosca `X+Y>Z` per scenario with harvest-now-decrypt-later detection, criticality, evidence
  confidence).
- Canonical JSON report with its own published schema; HTML (self-contained) and Markdown
  renderers; PDF via a pure-Go engine (default, offline) or an optional local-Chromium engine.
- `report` command with `--fail-on` policy gate; `diff` command with `--fail-on-regression`.
- Reproducible builds, CycloneDX SBOM of the tool, and cosign-signed checksums via GoReleaser;
  CI running lint, race tests, fuzzing, govulncheck, and a cross-compile matrix.

[Unreleased]: https://github.com/Aadil-Nabi/kvcbom/commits/main
