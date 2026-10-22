# Runbook: generate a PQC readiness report

How to produce a Post-Quantum Cryptographic (PQC) readiness report from a CycloneDX CBOM with
`kvcbom`. Follow it top to bottom — every command is copy-paste ready. For the exhaustive flag
reference see [`USAGE.md`](USAGE.md); this is the "what to run, in what order, and what to
check" guide.

`kvcbom` makes **no network calls** — rule packs, schemas, and templates are embedded, so the
whole procedure runs on an air-gapped host.

> Examples use Windows `cmd.exe` (`\` paths, `bin\kvcbom.exe`). On macOS/Linux swap to `/` and
> `./bin/kvcbom`.

---

## Quick start

Put everything in **one folder** anywhere on your drive (nothing needs to be installed — the
rule packs, schemas, and templates are baked into the exe). You end up with:

```
C:\pqc-assessment\            <- any folder you like
├─ kvcbom.exe                 <- the tool               (do not edit)
├─ kvcbom.yaml                <- run profile            (EDIT: paths + choices)
├─ context.yaml               <- your environment       (EDIT: systems, ports, data)
├─ crypto-bom.cdx.json        <- your CBOM from a scanner (bring it; do not edit)
└─ out-final\                 <- created on run; reports land here
```

**1 — Drop these files in the folder:** `kvcbom.exe`, your CBOM, and copies of the two samples
renamed: `report-config.example.yaml` → `kvcbom.yaml`, and `context-sample.yaml` →
`context.yaml`.

**2 — Edit `kvcbom.yaml`** so the paths are just the filenames in this folder:

```yaml
cbom:
  - crypto-bom.cdx.json       # your CBOM's filename
context: context.yaml
framework: [csa-qri-sg, nist-ir-8547]   # regulator overlays (optional)
format: [html, pdf, json]
out: out-final
force: true
```

**3 — Edit `context.yaml`** to describe your environment (systems, ports, data classes — see
[§2](#2-edit-your-two-files)).

**4 — Open a terminal in that folder and run:**

```cmd
kvcbom.exe validate --cbom crypto-bom.cdx.json --context context.yaml
kvcbom.exe report
start out-final\report.html
```

`report` with no flags auto-loads `kvcbom.yaml` from the current folder (it prints
`using config kvcbom.yaml`). That's the whole thing; the sections below explain each part.

---

## What you edit vs. what you leave alone

| File | In the folder? | You… |
|---|---|---|
| `kvcbom.exe` | yes | **leave alone** (the tool). |
| `context.yaml` (from `context-sample.yaml`) | yes | **edit** — your systems, ports, data classes. The real work. |
| `kvcbom.yaml` (from `report-config.example.yaml`) | yes | **edit** — filenames + which outputs/overlays. |
| your CBOM (`*.cdx.json`) | yes | **bring it** — your scanner's output; never hand-edit. |
| rule packs / schemas / templates | **no** | embedded in the exe — nothing to copy. |
| `baseline-pqc` classifier, regulator overlays | no | leave alone (overlays only if you do the [`REGULATORS.md`](REGULATORS.md) content task). |

Only in special cases you'd also add: a `cbom-mapping.yaml` (if your scanner hides the algorithm
in a vendor property — every asset shows `unknown`), or a manual register `.xlsx`/`.csv` +
`register-mapping.yaml`.

---

## 0. Prerequisites

| Need | How |
|---|---|
| The `kvcbom` binary | Build it (below) or use a release binary on `PATH`. |
| Go 1.25+ (only to build) | `go version` |
| A CBOM to assess | CycloneDX **1.6 or 1.7** JSON/XML from any scanner (AgileSec/Keyfactor, QuSecure, cbomkit, …). |
| A context file (recommended) | Maps endpoints to business systems and data classes; without it there is no Mosca/HNDL business scoring. See [`CONTEXT.md`](CONTEXT.md). |

**Build the binary** (from the repo root, e.g. `C:\Users\<you>\Desktop\dev\pqc\kvcbom`):

```cmd
go build -o bin\kvcbom.exe .\cmd\kvcbom
bin\kvcbom.exe version
```

macOS/Linux: `go build -o bin/kvcbom ./cmd/kvcbom && ./bin/kvcbom version`.

Then copy `bin\kvcbom.exe` into your working folder (next section) — or, if you were handed a
release binary, just use that. The examples below assume you run `kvcbom.exe` from the folder
that holds it.

---

## 1. Your working folder

Create a folder anywhere (e.g. `C:\pqc-assessment\`) and place in it:

- **`kvcbom.exe`** — the tool.
- **Your CBOM** — the CycloneDX file from your scanner (any name, e.g. `crypto-bom.cdx.json`).
  Several CBOMs are allowed; list them all under `cbom:`.
- **`context.yaml`** — a copy of `context-sample.yaml`, edited (next section).
- **`kvcbom.yaml`** — a copy of `report-config.example.yaml`, edited (next section).

The two samples ship with the tool: `report-config.example.yaml` is in the release archive
(or the repo root), and `context-sample.yaml` is under `testdata\` (or `docs`/the archive).
Nothing else is needed — rule packs, schemas, and templates are inside the exe.

---

## 2. Edit your two files

### `context.yaml` — your environment (the important one)

This is what makes the assessment *yours*. Edit:

- **`meta`** — `organisation`, `assessor`, `scope` (shown on the cover).
- **`systems`** — your business systems: `name`, `criticality` (critical/high/medium/low),
  `crown_jewel`, their `data_class_refs`, and `migration_time_years`.
- **`link_rules`** — ⚠️ **the most important part.** Maps CBOM endpoints to your systems by
  pattern; the sample matches by port (`:443$`, `:22$`, `:3306$`). These **must match how your
  CBOM writes its locations**, or every asset ends up `(unlinked)` and the per-system view is
  empty.
- **`data_classes`** — your data types and `confidentiality_lifetime_years` (the "X" in Mosca —
  how long the data must stay secret).
- **`crqc_scenarios`** — your years-until-quantum assumptions (defaults 7/12/20 are reasonable).

See [`CONTEXT.md`](CONTEXT.md) for the full format.

### `kvcbom.yaml` — the run profile

Just filenames (relative to this file's folder) and choices:

```yaml
cbom:
  - crypto-bom.cdx.json       # your CBOM's filename
context: context.yaml
framework: [csa-qri-sg, nist-ir-8547]   # regulator overlays; remove the line for none
format: [html, pdf, json]
out: out-final
force: true
# optional: org, title, timestamp, pdf-engine, fail-on, register, cbom-mapping …
```

How the profile behaves:

- **Every `report` flag has a matching key** — any option can go here instead of on the command
  line. Keys are the flag names.
- **Omitted keys fall back to defaults** — `rulepack` → `baseline-pqc`; `org`/`title` come from
  the context file / a built-in default, so you rarely set them.
- **Flags override the file** — `report --format md` writes Markdown only, whatever the file
  says. Handy for one-off tweaks.
- **Relative paths resolve against the profile's folder**, so the whole folder is portable — move
  or copy it anywhere and it still runs. Absolute paths are used as-is.
- **Auto-load**: with no `--config`, `kvcbom.yaml` in the current folder loads automatically (it
  prints `using config kvcbom.yaml`). An explicit `--config <path>` always wins.

Prefer flags instead? Skip the profile — section 4 (Option B) shows the explicit command.

---

## 3. Validate the inputs first

Always validate before generating. Read-only; it schema-checks each CBOM and lists completeness
gaps (missing fields that weaken scoring).

```cmd
kvcbom.exe validate --cbom crypto-bom.cdx.json --context context.yaml
```

- Exit `0` + `All inputs valid.` → proceed.
- Exit `2` → a schema failure, or (with `--strict`) a completeness warning. Fix the input or add
  a `--cbom-mapping`. `report` itself is schema-**tolerant** (it warns and proceeds on a stray
  1.7 field in a 1.6 document); `validate` is the strict gate.

Add `--strict` to fail on completeness warnings, or `--json` for machine-readable output.

---

## 4. Generate the report

### Option A — with a profile (recommended)

With `kvcbom.yaml` in the current folder, just:

```cmd
kvcbom.exe report
```

Or point at a named profile explicitly:

```cmd
kvcbom.exe report --config my-profile.yaml
```

### Option B — all on the command line

Everything as flags, no profile (single line; fixed `--timestamp` for a byte-reproducible run):

```cmd
kvcbom.exe report --cbom crypto-bom.cdx.json --context context.yaml --framework csa-qri-sg --framework nist-ir-8547 --format html,pdf,json --out out-final --force --timestamp 2026-01-01T00:00:00Z
```

(`--rulepack baseline-pqc` is the default; `--org`/`--title` come from the context file / the
built-in default — so none are needed here.)

### Open the result

```cmd
start out-final\report.html
start out-final\report.pdf
```

### `report` options (flag ⇄ profile key)

| Flag / key | Default | Purpose |
|---|---|---|
| `cbom` | — | CBOM file. **Repeatable** — several merge into one assessment. One of `cbom`/`register` is required. |
| `context` | — | Context file (systems, data classes, CRQC scenarios). Drives Mosca/HNDL scoring. |
| `rulepack` | `baseline-pqc` | The **classifier** pack. Leave as-is unless you maintain your own. |
| `framework` | — | A **regulator overlay** mapping findings onto its controls. **Repeatable** — one report can speak to several: `csa-qri-sg`, `nist-ir-8547`, `cnsa-2.0`, `enisa-eu`, `uk-ncsc`. |
| `format` | `json` | Any of `json,html,md,pdf`. JSON is the canonical source of truth; the rest render from it. |
| `out` | — | Output directory. **Required.** |
| `force` | `false` | Allow writing into a non-empty directory (re-runs). |
| `org` | — | Organisation on the cover (overrides the context value). |
| `title` | *(built-in)* | Report title. Defaults to "Post-Quantum Cryptographic Readiness Assessment". |
| `timestamp` | now | RFC3339 time stamped into the report. Fix it (or set `SOURCE_DATE_EPOCH`) for byte-reproducible output. |
| `fail-on` | — | CI gate: exit `3` if any finding is at/above this severity (`critical\|high\|medium\|low\|info`). |
| `pdf-engine` | `purego` | `purego` (offline) or `chromium` (needs a local browser; higher-fidelity PDF). |
| `cbom-mapping` | — | Vendor property-mapping YAML (see Troubleshooting). |
| `register`, `register-mapping` | — | Fold in a manual `.xlsx`/`.csv` register and its column mapping. |

The overlays above (`csa-qri-sg`, `nist-ir-8547`) ship **structure-only**: their control text is
a `TODO(source)` placeholder, so the report shows an "unverified content" warning until a human
fills them from the official documents per [`REGULATORS.md`](REGULATORS.md). Everything else —
findings, HNDL, Mosca, per-system view, remediation — is fully real.

---

## 5. Review the report before sharing

Open `report.html` (or `.pdf`) and check, in order:

1. **Warnings box** — read every line. Expect the "unverified framework mappings" note (until
   overlays are filled) and possibly "N assets could not be classified" (normal for bare
   protocol endpoints / key containers that name no single algorithm).
2. **Executive summary** — total assets, total findings, and the **HNDL exposure** count.
3. **Inventory** — sanity-check the by-quantum-status split; a large `unknown` count suggests a
   `--cbom-mapping` is needed.
4. **Findings** — the grouped critical/high/medium/info entries with explanations.
5. **Per-system view** — confirm your crown-jewel systems are present and scored (this comes
   from the context file; a missing system means the context mapping didn't match).
6. **Framework mapping** — which overlays are attached and whether they are verified.
7. **Affected assets** — the actionable algorithm list with roles and locations.

If the per-system view is empty or all `(unlinked)`, the context file's endpoint/location
patterns didn't match the CBOM — revisit [`CONTEXT.md`](CONTEXT.md).

---

## 6. Common variations

Shown as flags; each has an equivalent profile key.

**Minimal technical assessment** (no regulator overlay):

```cmd
bin\kvcbom.exe report --cbom <cbom> --context <context.yaml> --format html,pdf --out out-base --force
```

**All five regulators in one report:**

```cmd
bin\kvcbom.exe report --cbom <cbom> --context <context.yaml> --framework csa-qri-sg --framework nist-ir-8547 --framework cnsa-2.0 --framework enisa-eu --framework uk-ncsc --format html --out out-all --force
```

**Merge multiple CBOMs:**

```cmd
bin\kvcbom.exe report --cbom scan-dc1.cdx.json --cbom scan-dc2.cdx.json --context <context.yaml> --out out-merged --force
```

**Scanner that hides the algorithm in a vendor property:**

```cmd
bin\kvcbom.exe report --cbom <cbom> --cbom-mapping my-scanner-mapping.yaml --context <context.yaml> --out out-vendor --force
```

**Higher-fidelity PDF via a local browser:**

```cmd
bin\kvcbom.exe report --cbom <cbom> --context <context.yaml> --format pdf --pdf-engine chromium --out out-pdf --force
```

---

## 7. CI gating and tracking progress

**Fail a pipeline on risk** — exit `3` when any finding is critical:

```cmd
bin\kvcbom.exe report --cbom <cbom> --out out-ci --force --fail-on critical
echo exit: %ERRORLEVEL%
```

**Compare two assessments** and fail CI if risk rose:

```cmd
bin\kvcbom.exe diff --baseline old\report.json --current out-final\report.json --format md --out out-diff
bin\kvcbom.exe diff --baseline old\report.json --current out-final\report.json --fail-on-regression
```

`diff` consumes the canonical `report.json` from each run — always keep the JSON.

---

## 8. What gets written

Into `out`:

| File | When | Notes |
|---|---|---|
| `report.json` | `format` includes `json` | Canonical source of truth; feed it to `diff`. **Keep this.** |
| `report.html` | includes `html` | Self-contained single file, no external assets. Full technical artifact. |
| `report.pdf` | includes `pdf` | Black-and-white, print-ready; full parity with the HTML. |
| `report.md` | includes `md` | Markdown rendering. |

---

## 9. Exit codes

| Code | Meaning | Typical cause |
|---|---|---|
| `0` | Success | — |
| `1` | Usage error | Bad flags / missing required input. |
| `2` | Input validation failure | CBOM failed schema, unreadable file, bad pack. |
| `3` | Policy threshold breached | `--fail-on` / `--fail-on-regression` tripped. |
| `4` | Internal error | Report assembly/render failure. |

Check it after a run: `echo exit: %ERRORLEVEL%` (cmd) or `$LASTEXITCODE` (PowerShell).

---

## 10. Reproducibility

Identical inputs + a fixed `timestamp` (or `SOURCE_DATE_EPOCH`) produce a **byte-identical**
report every run — including the PDF. Record the timestamp you used and the input SHA-256 the
report prints, so a reviewer can reproduce it exactly.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `output directory ... is not empty` | Re-running into a used `out`. | Set `force: true` (or `--force`), or use a fresh `out`. |
| PDF won't overwrite / "being used by another process" | The old `report.pdf` is open in a viewer. | Close the viewer, or write to a new `out`. |
| Nothing ran / unexpected inputs; saw `using config kvcbom.yaml` | A `kvcbom.yaml` in the folder was auto-loaded. | Intended shortcut. Rename/remove the file, or pass explicit flags (they override it). |
| Every asset is `unknown` in the inventory | Scanner stored the algorithm in a vendor property, not the component name. | Add a `cbom-mapping` YAML mapping that property key to the algorithm (see [`USAGE.md`](USAGE.md)). |
| `rule pack ... has no classification table (it is a framework overlay)` | An overlay (e.g. `csa-qri-sg`) was passed as `rulepack`. | Put overlays under `framework`; keep `rulepack: baseline-pqc`. |
| Framework mappings show **NO (TODO)** / "unverified content" warning | Overlay control text is still placeholder. | Fill it from the official document per [`REGULATORS.md`](REGULATORS.md); intentional until then. |
| Warning: "did not fully conform to CycloneDX 1.6" | A 1.7 field in a 1.6-declared document. | Informational — `report` proceeds. Use `validate` for a strict gate. |
| Per-system view empty / all `(unlinked)` | Context patterns didn't match CBOM locations. | Align the context `location_patterns`/endpoints with the CBOM; see [`CONTEXT.md`](CONTEXT.md). |
| `config ...: ...` parse error | Malformed `kvcbom.yaml`. | Check YAML indentation; keys must match the flag names. |
| `unknown --pdf-engine` / `chromium PDF engine unavailable` | Bad engine name or no local browser. | Use `pdf-engine: purego` (default, always available). |

---

## Reference

- [`USAGE.md`](USAGE.md) — every command and flag, and `--config` profiles.
- [`CONTEXT.md`](CONTEXT.md) — the context file format.
- [`RULEPACKS.md`](RULEPACKS.md) — classifier packs vs framework overlays.
- [`REGULATORS.md`](REGULATORS.md) — verifying a regulator overlay's control text.
- [`SCORING.md`](SCORING.md) — the risk model and Mosca inequality.
- [`DISTRIBUTION.md`](DISTRIBUTION.md) — shipping a prebuilt binary to others.
