# Rule packs

A rule pack is a single versioned YAML file. It supplies the standards content kvcbom itself
must never invent: the algorithm classification table, the rules that turn classifications into
findings, framework-control mappings, remediation guidance, and the scoring weights. Packs are
embedded for offline use and overridable from disk (`--rulepack ./my-pack.yaml`). Each pack is
validated against `schemas/rulepack/rulepack-1.schema.json`.

## Structure

```yaml
schema_version: 1
id: my-pack                 # lowercase; [a-z0-9._-]
version: 1.0.0              # semver
name: My Pack
description: >
  ...
status: final              # final | draft | vendor

sources:                   # every classification/mapping references one of these by id
  - id: fips-203
    title: "FIPS 203: ML-KEM"
    url: "https://doi.org/10.6028/NIST.FIPS.203"
    status: final
    retrieved_date: "2026-10-21"

classifications:
  - id: rsa
    quantum_status: shor_broken   # shor_broken | grover_weakened | quantum_resistant
                                  #  | classically_broken | unknown
    rationale: "RSA relies on integer factorisation, broken by Shor's algorithm."
    source: shor-1997             # MUST resolve to a declared source
    match:                        # every specified dimension must match (logical AND)
      name_patterns: ["(?i)\\brsa"]   # Go RE2 regex
      oids: ["1.2.840.113549.1.1.1"]  # exact
      param_sets: ["2048"]            # case-insensitive
      curves: ["P-256"]               # case-insensitive
      primitives: ["pke"]             # exact
      key_bits: { eq: 2048 }          # or { min: 256 } / { max: 128 }
    # optional, each with its own source:
    # deprecation:  { date: "...", source: ... }
    # disallowance: { date: "...", source: ... }

rules:
  - id: MP-ASYM
    title: "Quantum-vulnerable public-key algorithm"
    severity: critical           # critical | high | medium | low | info
    finding_type: quantum-vulnerable-asymmetric
    when: 'Status == "shor_broken"'   # expr-lang; see the environment below
    explanation: "..."
    remediation: migrate-asymmetric   # references a remediation id

remediation:
  - id: migrate-asymmetric
    summary: "Migrate to NIST PQC algorithms."
    detail: "..."
    references: [fips-203]            # must resolve to declared sources

framework:                            # optional (framework packs only)
  id: my-framework
  name: My Framework
  mappings:
    - finding_type: quantum-vulnerable-asymmetric
      control_id: "TODO(source): control id"      # TODO(source) until verified
      control_title: "TODO(source): text"
      source: my-framework-doc

scoring:
  weights: { quantum_vulnerability: 0.4, mosca_exposure: 0.3, criticality: 0.2, evidence_confidence: 0.1 }
  severity_scores: { critical: 100, high: 75, medium: 50, low: 25, info: 0 }
```

## Classification matching

An entry matches an asset when **every specified** `match` dimension matches; an entry with no
criteria never matches. When several entries match, the **most specific** wins — by a fixed
ordering (`oids` > `key_bits` > `param_sets` > `curves` > `name_patterns` > `primitives`) — and
ties break to the **earliest entry in pack order**. Because CycloneDX 1.6 carries no algorithm
family field, name patterns are the usual backbone; list post-quantum entries first so order
breaks substring collisions correctly (e.g. `ML-DSA` contains `DSA`).

## Rule expression environment

A rule's `when` is an [expr-lang](https://expr-lang.org) boolean expression over these fields:

`Type`, `Name`, `ParameterSet`, `KeySizeBits` (int), `HasKeySize` (bool), `Mode`, `Primitive`,
`Curve`, `OID`, `Functions` ([]string), `Status` (the quantum status), `MatchedEntry` (the
classification entry id).

## Validation rules

`kvcbom rulepacks validate <id|path>`:

- **Error** (exit 2): schema violation, bad regex, a classification/milestone/mapping/remediation
  reference that names no declared source, duplicate ids, or a `when` expression that does not
  compile.
- **Warning**: a remaining `TODO(source):` marker, or a classification with no match criteria.

A pack that is `draft`/`vendor` status, or that still contains `TODO(source):` markers, causes
every report built with it to show an "unverified rule content" warning.
