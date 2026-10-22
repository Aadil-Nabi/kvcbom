# Usage

`kvcbom` has no runtime network access. All rule packs, schemas, and templates are embedded.
CBOMs are accepted from any tool: both **CycloneDX 1.6 and 1.7** are validated against the
matching embedded schema (selected from the document's `specVersion`), and `--cbom-mapping`
adapts to a scanner that records the algorithm in a vendor-specific property.

## Global flags

| Flag | Default | Meaning |
|---|---|---|
| `--log-level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `--log-format` | `text` | `text` \| `json` |
| `--no-color` | `false` | Disable coloured output |
| `--config` | — | A `report` profile (YAML) — see below |

Configuration precedence: flags > config file > defaults.

### `--config` (report profiles)

`report` can take its inputs and options from a YAML profile instead of a long command line:
`kvcbom report --config kvcbom.yaml`. The keys mirror the `report` flag names
(`cbom`, `context`, `rulepack`, `framework`, `format`, `out`, `force`, `org`, `title`,
`timestamp`, `fail-on`, `pdf-engine`, `register`, `register-mapping`, `cbom-mapping`). An
explicit flag overrides the file; omitted keys fall back to their defaults. Relative paths in
the file resolve against the file's own folder, so a profile is portable. A ready-to-edit
sample ships at [`report-config.example.yaml`](../report-config.example.yaml).

With **no** `--config`, `report` auto-loads a `kvcbom.yaml` (or `kvcbom.yml`) from the current
directory if one is present, so `kvcbom report` alone runs the whole assessment (it prints
`using config kvcbom.yaml`). An explicit `--config <path>` always takes precedence.

## `validate`

Schema-checks each CBOM against CycloneDX 1.6 and lists fields whose absence weakens scoring.
An optional context file is validated too.

```sh
kvcbom validate --cbom a.cbom.json --cbom b.cbom.xml --context context.yaml
kvcbom validate --cbom a.cbom.json --json           # machine-readable to stdout
kvcbom validate --cbom a.cbom.json --strict         # completeness warnings fail (exit 2)
```

| Flag | Meaning |
|---|---|
| `--cbom` | CBOM file (repeatable) |
| `--context` | Context file to validate |
| `--strict` | Treat completeness warnings as failures |
| `--json` | Emit JSON to stdout (human table to stderr otherwise) |
| `--max-bytes` | Per-file size limit (0 = default) |

## `report`

Runs the full pipeline and writes the report into `--out`.

```sh
kvcbom report \
  --cbom app.cbom.json --register assets.xlsx --context context.yaml \
  --rulepack baseline-pqc --format json,html,md,pdf --out ./out \
  --title "ACME PQC Readiness" --org "ACME" --timestamp 2026-01-01T00:00:00Z
```

| Flag | Default | Meaning |
|---|---|---|
| `--cbom` | — | CBOM file (repeatable) |
| `--register` | — | Manual register (`.xlsx` or `.csv`) |
| `--register-mapping` | built-in | Column-mapping YAML for the register |
| `--cbom-mapping` | built-in | CBOM extension-mapping YAML: which vendor property keys carry the algorithm |
| `--context` | — | Assessment context file |
| `--rulepack` | `baseline-pqc` | Pack id or path |
| `--format` | `json` | Any of `json,html,md,pdf` |
| `--out` | — | Output directory (required) |
| `--pdf-engine` | `purego` | `purego` (offline) or `chromium` (local browser) |
| `--title`, `--org` | — | Report title / organisation (org overrides the context value) |
| `--timestamp` | now | RFC3339 timestamp for reproducible output |
| `--force` | `false` | Write into a non-empty output directory |
| `--fail-on` | — | Exit 3 if any finding is at or above `critical\|high\|medium\|low\|info` |

Reproducible output: pass `--timestamp`, or set `SOURCE_DATE_EPOCH`. The JSON report is then
byte-identical across runs; the pure-Go PDF is byte-identical too.

## `diff`

Compares two canonical `report.json` files.

```sh
kvcbom diff --baseline old/report.json --current new/report.json           # Markdown to stdout
kvcbom diff --baseline old/report.json --current new/report.json \
  --format json,md --out ./diff
kvcbom diff --baseline old/report.json --current new/report.json \
  --fail-on-regression                                                      # exit 3 if risk rose
```

## `rulepacks`

```sh
kvcbom rulepacks list                 # embedded packs
kvcbom rulepacks show baseline-pqc    # metadata, sources, rules
kvcbom rulepacks validate ./my.yaml   # exit 2 on any error; warns on TODO(source)
```

## Exit codes

`0` success · `1` usage error · `2` input validation failure · `3` policy threshold breached ·
`4` internal error.
