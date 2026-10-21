# The assessment context file

The context file (YAML) carries the business information a CBOM cannot: which systems use
which crypto, how long data must stay secret, how long migration will take, and when a
cryptographically relevant quantum computer (CRQC) might arrive. It is optional — without it,
assets are still classified, but Mosca exposure and criticality cannot be computed.

It is validated against an embedded JSON Schema (`schemas/context/context-1.schema.json`).

## Example

```yaml
schema_version: 1
meta:
  organisation: ACME Ltd
  assessor: Security Team
  scope: Internet-facing services
global_migration_time_years: 5          # Y default, overridable per system
crqc_scenarios:                          # Z — always your assumptions, never a hardcoded fact
  - { name: optimistic,  years_until: 20 }
  - { name: central,     years_until: 12 }
  - { name: pessimistic, years_until: 7 }
data_classes:
  - { id: pii,       name: Personal Data, confidentiality_lifetime_years: 15 }  # X
  - { id: ephemeral, name: Session Data,  confidentiality_lifetime_years: 1 }
systems:
  - id: payments
    name: Payments API
    owner: payments-team
    criticality: critical        # low | medium | high | critical
    crown_jewel: true            # forces criticality to the maximum
    data_class_refs: [pii]
    migration_time_years: 3      # overrides the global default for this system
  - id: logging
    name: Logging Pipeline
    criticality: low
    data_class_refs: [ephemeral]
link_rules:                      # attach CBOM assets to systems
  - system_ref: payments
    name_patterns: ["(?i)rsa", "(?i)ecdsa"]       # Go RE2 regex on the asset/algorithm name
    location_patterns: [":443$", ":8443$"]        # Go RE2 regex on the asset's locations
  - system_ref: logging
    bom_refs: ["alg:aes-logging"]                 # exact CycloneDX bom-ref match
```

`location_patterns` are the usual way to link **scanner** CBOMs: those name each asset by its
endpoint (e.g. `172.31.100.76:443`), which kvcbom records as the asset's location, so you map
by port or host. A worked example that maps the bundled scanner CBOM lives at
[`testdata/context-sample.yaml`](../testdata/context-sample.yaml).

## How linking works

An asset is attached to a system when a link rule matches it — by `bom_refs` (exact match on
any of the asset's evidence `bom-ref`s) or by `name_patterns` (a regular expression against the
asset name). A linked asset inherits that system's data classes, which supply the Mosca **X**
term. `kvcbom validate --context <file>` reports dangling references and other gaps.

See [`SCORING.md`](SCORING.md) for how X (confidentiality lifetime), Y (migration time), and Z
(years until CRQC) combine.
