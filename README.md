# kvcbom

**Post-Quantum Cryptographic (PQC) readiness assessment & report generator.**

`kvcbom` consumes **CycloneDX 1.6 Cryptographic Bills of Materials (CBOMs)** (plus optional
manual registers and business context), risk-scores the inventoried cryptographic assets for
quantum exposure, maps findings to readiness frameworks, and produces shareable reports
(JSON / HTML / Markdown / PDF).

- **Air-gap safe** — no network calls at runtime; rule packs, templates, and schemas are embedded.
- **Single static binary** (`CGO_ENABLED=0`) for linux/macOS/windows on amd64/arm64.
- **Deterministic & traceable** — identical inputs produce byte-identical JSON; every finding
  traces to its input file, `bom-ref`, rule ID, and rule-pack version, and reports record the
  SHA-256 of every input and the rule pack.
- **No invented standards content** — algorithm classifications cite primary sources; framework
  control text that has not been verified is shown as a `TODO(source):` placeholder.

## Install

```sh
go install github.com/Aadil-Nabi/kvcbom/cmd/kvcbom@latest
# or build from a checkout:
make build   # -> ./bin/kvcbom
```

## Quick start

```sh
# Validate a CBOM against CycloneDX 1.6 and list completeness gaps
kvcbom validate --cbom app.cbom.json

# Full assessment -> JSON + HTML + PDF into ./out
kvcbom report --cbom app.cbom.json --context context.yaml \
  --format json,html,pdf --out ./out

# Fail CI when a critical finding is present
kvcbom report --cbom app.cbom.json --out ./out --fail-on critical

# Track progress between two assessments
kvcbom diff --baseline old/report.json --current new/report.json

# Inspect the bundled rule packs
kvcbom rulepacks list
kvcbom rulepacks show baseline-pqc
```

## What it does

```
ingest (CBOM / register / context) -> validate -> normalise & merge -> classify
  -> score (quantum vulnerability + Mosca X+Y>Z per scenario + criticality + evidence)
  -> map to framework -> render report (JSON / HTML / Markdown / PDF)
```

The canonical **JSON** report is the source of truth; HTML, Markdown, and PDF are rendered from
it, and `diff` consumes it.

## Commands

| Command | Purpose |
|---|---|
| `validate` | Schema-check CBOMs (and an optional context file) and report completeness gaps. |
| `report` | Run the full pipeline and write a report; `--fail-on` gates CI. |
| `diff` | Compare two report JSON files; `--fail-on-regression` gates CI. |
| `rulepacks list\|show\|validate` | Inspect and validate rule packs. |
| `version` | Print version, commit, and build date. |

**Exit codes:** `0` success · `1` usage error · `2` input validation failure ·
`3` policy threshold breached (`--fail-on` / `--fail-on-regression`) · `4` internal error.

## Documentation

- [`docs/USAGE.md`](docs/USAGE.md) — commands, flags, and examples.
- [`docs/CONTEXT.md`](docs/CONTEXT.md) — the assessment context file.
- [`docs/RULEPACKS.md`](docs/RULEPACKS.md) — writing and verifying a rule pack.
- [`docs/REGULATORS.md`](docs/REGULATORS.md) — fill-in checklist to verify a regulator overlay.
- [`docs/SCORING.md`](docs/SCORING.md) — the risk model and Mosca inequality.
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — architecture decision records.
- [`SECURITY.md`](SECURITY.md) — input-safety model and reporting.

## Rule packs

| Pack | Kind | Status | Notes |
|---|---|---|---|
| `baseline-pqc` | classifier | final | Quantum-vulnerability classification from established facts; every entry source-cited. |
| `nist-ir-8547` | overlay | draft | NIST IR 8547 transition mapping; control text as `TODO(source):`. |
| `cnsa-2.0` | overlay | draft | NSA CNSA 2.0 mapping; control text as `TODO(source):`. |
| `csa-qri-sg` | overlay | vendor | CSA Singapore mapping; control text as `TODO(source):`. |
| `enisa-eu` | overlay | draft | ENISA (EU) mapping; control text as `TODO(source):`. |
| `uk-ncsc` | overlay | draft | UK NCSC mapping; control text as `TODO(source):`. |

Classify with the `baseline-pqc` **classifier** (`--rulepack`) and add one or more regulator
**overlays** (`--framework`) to map the findings onto their controls — several in one report:

```sh
kvcbom report --cbom app.cbom.json --rulepack baseline-pqc \
  --framework csa-qri-sg --framework nist-ir-8547 --format html,pdf --out ./out
```

A report using a draft/vendor pack, or any overlay whose control text is still a
`TODO(source):` placeholder, carries a visible "unverified content" warning. Supports both
CycloneDX 1.6 and 1.7, and `--cbom-mapping` adapts to any scanner's property conventions.

## Development

```sh
make test      # go test ./...
make race      # with the race detector
make lint      # golangci-lint
make fuzz      # fuzz smoke tests
make cover     # coverage summary
make snapshot  # local GoReleaser build
```

## Licence

See [`LICENSE`](LICENSE). A licence has not yet been chosen; the placeholder reserves the file.
