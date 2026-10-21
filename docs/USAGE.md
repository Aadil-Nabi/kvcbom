# Usage

`kvcbom` has no runtime network access. All rule packs, schemas, and templates are embedded.

## Global flags

| Flag | Default | Meaning |
|---|---|---|
| `--log-level` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `--log-format` | `text` | `text` \| `json` |
| `--no-color` | `false` | Disable coloured output |
| `--config` | — | Reserved for a config file |

Configuration precedence: flags > environment (`KVCBOM_*`) > config file > defaults.

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
