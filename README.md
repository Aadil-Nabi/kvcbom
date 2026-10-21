# kvcbom

**Post-Quantum Cryptographic (PQC) readiness assessment & report generator.**

`kvcbom` consumes **CycloneDX 1.6 Cryptographic Bills of Materials (CBOMs)** (plus optional
manual registers and business context), risk-scores the inventoried cryptographic assets for
quantum exposure, maps findings to readiness frameworks, and produces shareable reports
(JSON / HTML / Markdown / PDF).

- **Air-gap safe** — no network calls at runtime; rule packs and templates are embedded.
- **Single static binary** (`CGO_ENABLED=0`), cross-platform.
- **Deterministic & traceable** — every finding traces to its input file, `bom-ref`, rule ID,
  and rule-pack version; reports record SHA-256 hashes of all inputs.

> **Status:** in development. Planning complete — see [`SPEC.md`](./SPEC.md),
> [`docs/PLAN.md`](./docs/PLAN.md), and [`docs/DECISIONS.md`](./docs/DECISIONS.md).
> Milestone M1 (model + CBOM ingest + `validate`) is next.

## Quick start

> _Full install/usage docs land with M6. For now, build from source:_

```bash
go build ./cmd/kvcbom      # (available from M1)
```

## License

TBD — a `LICENSE` placeholder will be added; no licence has been chosen yet (SPEC §10).
