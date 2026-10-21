# Security

## Runtime posture

`kvcbom` makes **no network calls** at runtime: no telemetry, no update checks, no remote rule
fetching. Rule packs, JSON schemas, and report templates are embedded in the binary, so the tool
runs fully offline on locked-down or air-gapped machines. The optional `--pdf-engine chromium`
launches a local browser with networking disabled solely to print the already-generated,
self-contained HTML to PDF.

## Input handling

Every input (CBOM, register, context, rule pack, baseline/current report) is treated as
untrusted:

- **Size limits** on every file read.
- **XML** is parsed with Go's `encoding/xml`, which resolves no DTDs or external entities; the
  decoder additionally runs in strict mode with an empty custom-entity map (no XXE).
- **Spreadsheet** ingestion caps rows; CSV parsing is bounded.
- **No path traversal**: output file names are confined to the chosen `--out` directory.
- **HTML output** is produced with `html/template` contextual auto-escaping. Input-derived text
  is never wrapped in `template.HTML`, so a crafted asset name cannot inject markup.
- **Rule expressions** run in the sandboxed `expr-lang` evaluator against a fixed, read-only
  environment — no arbitrary code execution.

Logs never include full input contents at info level.

## Integrity and traceability

Each report records the SHA-256 of every input file and of the rule pack, the tool version and
commit, and the rule-pack id and version. Released binaries are built reproducibly
(`-trimpath`, fixed module timestamp), ship a CycloneDX SBOM of the tool, and have their
checksums signed with cosign (keyless, via the release workflow's OIDC identity).

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainer rather than opening a public
issue, and allow reasonable time for a fix before disclosure. Include the version
(`kvcbom version`), the input that triggers the issue (minimised if possible), and the observed
versus expected behaviour.
