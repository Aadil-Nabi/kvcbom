# Runbook: generate a PQC readiness report

A step-by-step operational procedure for producing a Post-Quantum Cryptographic (PQC)
readiness report from a CycloneDX CBOM using `kvcbom`. Follow it top to bottom; every
command is copy-paste ready. For the exhaustive flag reference see [`USAGE.md`](USAGE.md);
this runbook is the "what to run, in what order, and what to check" guide.

`kvcbom` makes **no network calls**. Rule packs, schemas, and templates are embedded in the
binary, so the whole procedure runs on an air-gapped host.

---

## 0. Prerequisites

| Need | How |
|---|---|
| The `kvcbom` binary | Build it (below) or use a release binary on `PATH`. |
| Go 1.25+ (only to build) | `go version` |
| A CBOM to assess | CycloneDX **1.6 or 1.7** JSON/XML from any scanner (AgileSec/Keyfactor, QuSecure, cbomkit, etc.). |
| A context file (recommended) | Maps endpoints to business systems and data classes; without it, risk scoring has no Mosca/HNDL business input. See [`CONTEXT.md`](CONTEXT.md). |

**Build the binary** (run from the repo root, e.g. `C:\Users\<you>\Desktop\dev\pqc\kvcbom`):

```cmd
go build -o bin\kvcbom.exe .\cmd\kvcbom
bin\kvcbom.exe version
```

On macOS/Linux: `go build -o bin/kvcbom ./cmd/kvcbom && ./bin/kvcbom version`.

> All examples below use Windows `cmd.exe` syntax (`\` paths, `bin\kvcbom.exe`). On a POSIX
> shell, swap to `/` and `./bin/kvcbom`.

---

## 1. Collect your inputs

Put the paths to the following where you can reference them:

1. **CBOM file(s)** — one or more. Repeat `--cbom` to merge several into one assessment.
2. **Context file** (`context.yaml`) — optional but recommended. Defines the business
   systems, which endpoints belong to them, data-class confidentiality lifetimes, and the
   CRQC scenarios (years-until-quantum). A ready-made sample lives at
   `testdata\context-sample.yaml` — copy and edit it for your environment.
3. **CBOM mapping** (`--cbom-mapping`) — only if your scanner records the algorithm in a
   vendor-specific property (symptom: every asset comes back `unknown`; see Troubleshooting).
4. **Manual register** (`--register`, `.xlsx`/`.csv`) — only if you have crypto assets not in
   any CBOM and want to fold them in.

---

## 2. Validate the inputs first

Always validate before generating. This schema-checks each CBOM and lists completeness gaps
(missing fields that weaken scoring). It is read-only.

```cmd
bin\kvcbom.exe validate --cbom <path-to-cbom> --context <path-to-context.yaml>
```

Worked example (CBOM one level up in the `pqc` folder):

```cmd
bin\kvcbom.exe validate --cbom ..\cbom-PT8DJL3B9Z-2026-10-16.cdx.json --context testdata\context-sample.yaml
```

- Exit `0` and `All inputs valid.` → proceed.
- Exit `2` → a schema failure or (with `--strict`) a completeness warning. Fix the input or
  add a `--cbom-mapping`. Note: `report` is schema-**tolerant** (it warns and proceeds on a
  stray 1.7 field in a 1.6 document); `validate` is the strict gate.

Add `--strict` to fail on completeness warnings, or `--json` for machine-readable output.

---

## 3. Generate the report

The canonical, full-featured command. It classifies with the NIST-grounded `baseline-pqc`
pack and adds one or more regulator overlays:

```cmd
bin\kvcbom.exe report ^
  --cbom <path-to-cbom> ^
  --context <path-to-context.yaml> ^
  --rulepack baseline-pqc ^
  --framework csa-qri-sg ^
  --framework nist-ir-8547 ^
  --format html,pdf,json ^
  --out out-final ^
  --org "Example Corp" ^
  --title "Post-Quantum Cryptographic Readiness Assessment" ^
  --force
```

Worked example matching the sample setup (single line, with a fixed timestamp for a
reproducible, byte-identical report):

```cmd
bin\kvcbom.exe report --cbom ..\cbom-PT8DJL3B9Z-2026-10-16.cdx.json --context testdata\context-sample.yaml --rulepack baseline-pqc --framework csa-qri-sg --framework nist-ir-8547 --format html,pdf,json --out out-final --force --timestamp 2026-01-01T00:00:00Z
```

Open the result:

```cmd
start out-final\report.html
start out-final\report.pdf
```

### `report` flags used above

| Flag | Default | Purpose |
|---|---|---|
| `--cbom` | — | CBOM file. **Repeatable** — pass several to merge them. One of `--cbom`/`--register` is required. |
| `--context` | — | Context file (systems, data classes, CRQC scenarios). Drives Mosca/HNDL scoring. |
| `--rulepack` | `baseline-pqc` | The **classifier** pack. Leave as `baseline-pqc` unless you maintain your own classifier. |
| `--framework` | — | A **regulator overlay** to map findings onto its controls. **Repeatable** — one report can speak to several regulators. Overlays: `csa-qri-sg`, `nist-ir-8547`, `cnsa-2.0`, `enisa-eu`, `uk-ncsc`. |
| `--format` | `json` | Any of `json,html,md,pdf` (comma-separated). JSON is the canonical source of truth; the others render from it. |
| `--out` | — | Output directory. **Required.** |
| `--force` | `false` | Allow writing into a non-empty directory (re-runs). |
| `--org` | — | Organisation name on the cover (overrides the context value). |
| `--title` | — | Report title. |
| `--timestamp` | now | RFC3339 time stamped into the report. Fix it (or set `SOURCE_DATE_EPOCH`) for byte-reproducible output. |
| `--fail-on` | — | CI gate: exit `3` if any finding is at/above this severity (`critical\|high\|medium\|low\|info`). |
| `--pdf-engine` | `purego` | `purego` (offline, single binary) or `chromium` (needs a local browser; higher-fidelity PDF). |
| `--cbom-mapping` | — | Vendor property-mapping YAML (see Troubleshooting). |
| `--register`, `--register-mapping` | — | Fold in a manual `.xlsx`/`.csv` register and its column mapping. |

The two overlays above (`csa-qri-sg`, `nist-ir-8547`) are shipped **structure-only**: their
control text is a `TODO(source)` placeholder, so the report shows an "unverified content"
warning until a human fills them from the official documents per [`REGULATORS.md`](REGULATORS.md).
Everything else — findings, HNDL, Mosca, per-system view, remediation — is fully real.

---

## 4. Review the report before sharing

Open `report.html` (or `.pdf`) and check, in order:

1. **Warnings box** — read every line. Expect the "unverified framework mappings" note (until
   overlays are filled) and possibly an "N assets could not be classified" note (normal for
   bare protocol endpoints / key containers that name no single algorithm).
2. **Executive summary** — total assets, total findings, and the **HNDL exposure** count.
3. **Inventory** — sanity-check the by-quantum-status split; a large `unknown` count may mean
   you need a `--cbom-mapping`.
4. **Findings** — the grouped critical/high/medium/info entries with explanations.
5. **Per-system view** — confirm your crown-jewel systems are present and scored (this comes
   from the context file; if a system is missing, your context mapping didn't match).
6. **Framework mapping** — confirms which overlays are attached and whether they are verified.
7. **Affected assets** — the actionable algorithm list with roles and locations.

If the per-system view is empty or everything is `(unlinked)`, your context file's
endpoint/location patterns didn't match the CBOM — revisit [`CONTEXT.md`](CONTEXT.md).

---

## 5. Common variations

**Minimal technical assessment** (no regulator overlay, HTML + PDF only):

```cmd
bin\kvcbom.exe report --cbom <cbom> --context <context.yaml> --rulepack baseline-pqc --format html,pdf --out out-base --force
```

**All five regulators in one report:**

```cmd
bin\kvcbom.exe report --cbom <cbom> --context <context.yaml> --rulepack baseline-pqc --framework csa-qri-sg --framework nist-ir-8547 --framework cnsa-2.0 --framework enisa-eu --framework uk-ncsc --format html --out out-all --force
```

**Merge multiple CBOMs:**

```cmd
bin\kvcbom.exe report --cbom scan-dc1.cdx.json --cbom scan-dc2.cdx.json --context <context.yaml> --out out-merged --force
```

**Scanner that hides the algorithm in a vendor property** (add a mapping):

```cmd
bin\kvcbom.exe report --cbom <cbom> --cbom-mapping my-scanner-mapping.yaml --context <context.yaml> --out out-vendor --force
```

**Higher-fidelity PDF via a local browser:**

```cmd
bin\kvcbom.exe report --cbom <cbom> --context <context.yaml> --format pdf --pdf-engine chromium --out out-pdf --force
```

---

## 6. CI gating and tracking progress

**Fail a pipeline on risk** — exit code `3` when any finding is critical:

```cmd
bin\kvcbom.exe report --cbom <cbom> --out out-ci --force --fail-on critical
echo exit: %ERRORLEVEL%
```

**Compare two assessments** (e.g. last quarter vs this quarter) and fail CI if risk rose:

```cmd
bin\kvcbom.exe diff --baseline old\report.json --current out-final\report.json --format md --out out-diff
bin\kvcbom.exe diff --baseline old\report.json --current out-final\report.json --fail-on-regression
```

`diff` consumes the canonical `report.json` from each run; always keep the JSON.

---

## 7. What gets written

Into `--out`:

| File | When | Notes |
|---|---|---|
| `report.json` | `--format` includes `json` | Canonical source of truth; feed it to `diff`. **Keep this.** |
| `report.html` | includes `html` | Self-contained, single file, no external assets. The full technical artifact. |
| `report.pdf` | includes `pdf` | Black-and-white, print-ready; full parity with the HTML. |
| `report.md` | includes `md` | Markdown rendering. |

---

## 8. Exit codes

| Code | Meaning | Typical cause |
|---|---|---|
| `0` | Success | — |
| `1` | Usage error | Bad flags / missing required flag. |
| `2` | Input validation failure | CBOM failed schema, unreadable file, bad pack. |
| `3` | Policy threshold breached | `--fail-on` / `--fail-on-regression` tripped. |
| `4` | Internal error | Report assembly/render failure. |

---

## 9. Reproducibility

Identical inputs + a fixed `--timestamp` (or `SOURCE_DATE_EPOCH`) produce a **byte-identical**
report every run — including the PDF. Record the `--timestamp` you used and the input SHA-256
that the report prints, so a reviewer can reproduce it exactly.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `output directory ... is not empty` | Re-running into a used `--out`. | Add `--force`, or point `--out` at a fresh directory. |
| PDF won't overwrite / "being used by another process" | The old `report.pdf` is open in a viewer. | Close the viewer, or write to a new `--out`. |
| Every asset is `unknown` in the inventory | The scanner stored the algorithm in a vendor property, not the component name. | Write a `--cbom-mapping` YAML mapping that property key to the algorithm (see [`USAGE.md`](USAGE.md)). |
| `rule pack ... has no classification table (it is a framework overlay)` | An overlay (e.g. `csa-qri-sg`) was passed to `--rulepack`. | Pass overlays via `--framework`; keep `--rulepack baseline-pqc`. |
| Framework mappings show **NO (TODO)** / "unverified content" warning | Overlay control text is still placeholder. | Fill it from the official document per [`REGULATORS.md`](REGULATORS.md); intentional until then. |
| Warning: "did not fully conform to CycloneDX 1.6" | A 1.7 field in a 1.6-declared document. | Informational — `report` proceeds. Use `validate` for a strict gate. |
| Per-system view empty / all `(unlinked)` | Context patterns didn't match CBOM locations. | Align the context `location_patterns`/endpoints with the CBOM; see [`CONTEXT.md`](CONTEXT.md). |
| `unknown --pdf-engine` / `chromium PDF engine unavailable` | Bad engine name or no local browser. | Use `--pdf-engine purego` (default, always available). |

---

## Reference

- [`USAGE.md`](USAGE.md) — every command and flag.
- [`CONTEXT.md`](CONTEXT.md) — the context file format.
- [`RULEPACKS.md`](RULEPACKS.md) — classifier packs vs framework overlays.
- [`REGULATORS.md`](REGULATORS.md) — verifying a regulator overlay's control text.
- [`SCORING.md`](SCORING.md) — the risk model and Mosca inequality.
