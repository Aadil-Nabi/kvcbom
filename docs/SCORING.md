# Scoring

Every asset gets a `RiskScore` whose components are reported individually — no opaque number.
The final value is a weighted sum in `[0,1]` using the rule pack's weights:

```
final = ( wQ·quantum_vulnerability
        + wM·mosca_exposure
        + wC·criticality
        + wE·evidence_confidence ) / (wQ + wM + wC + wE)
```

Default weights (configurable per pack): `wQ=0.4, wM=0.3, wC=0.2, wE=0.1`.

## Quantum vulnerability

From the classification status:

| Status | Value |
|---|---|
| `shor_broken` | 1.0 |
| `classically_broken` | 1.0 |
| `grover_weakened` | 0.5 |
| `unknown` | 0.3 |
| `quantum_resistant` | 0.0 |

`unknown` is non-zero on purpose: an unclassified asset still warrants attention.

## Mosca exposure

For each CRQC scenario, the Mosca inequality is evaluated:

```
X + Y > Z
```

- **X** — confidentiality lifetime (years the data must stay secret), the maximum over the
  asset's linked data classes.
- **Y** — migration time (years), the linked system's override or the global default.
- **Z** — years until a cryptographically relevant quantum computer, per user-supplied scenario.

An asset is **exposed** in a scenario when `X + Y > Z` **and** it is quantum-vulnerable
(`shor_broken` or `grover_weakened`). The Mosca component is the fraction of scenarios in which
the asset is exposed. It is computed only when the asset is linked to at least one data class;
otherwise it is zero and the score records a note.

**Harvest-now-decrypt-later (HNDL)** is flagged when an exposed asset is `shor_broken` and
performs confidentiality protection (key establishment — `pke`/`kem`/`key-agree` — or an
`encrypt`/`encapsulate`/`keyderive`/`keygen` function): an adversary can capture ciphertext now
and decrypt it once a CRQC exists.

## Criticality

The highest criticality among the asset's linked systems (`low`=0.25 … `critical`=1.0); a
crown-jewel system is treated as `critical`. With no linked system it defaults to `medium` (0.5)
and the score records a note.

## Evidence confidence

Evidence is graded C1–C4 (C1 weakest/asserted, C4 strongest/verified-from-live-config). The
component is `C1=0.25 … C4=1.0` (the asset's strongest evidence). Confidence informs the score
only lightly (`wE=0.1`); more importantly, any finding resting on C1/C2 evidence is marked
**requires verification** so weak evidence is surfaced rather than silently trusted or
discounted.

## Policy gate

`kvcbom report --fail-on <severity>` exits with code `3` when any finding is at or above the
given severity — for CI/CD. Reports are always written before the gate fails.
