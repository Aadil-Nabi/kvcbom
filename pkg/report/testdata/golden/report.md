# Test Readiness Report

**Organisation:** Example Corp  
**Scope:** Web tier  
**Assessor:** Sec Team  
**Generated:** 2026-01-01T00:00:00Z  
**Tool:** kvcbom 1.0.0-test  
**Rule pack:** baseline-pqc 1.0.0 (final)  

**Inputs:**

- `bom.json` — `sha-of-bom`

## Warnings

- 2 finding(s) rest on low-confidence evidence (C1/C2) and are marked as requiring verification
- 1 asset(s) could not be classified — typically protocol endpoints (TLS/SSH/IKE) and key containers (e.g. JKS, PKCS#12) that do not name a single algorithm, rather than assessment failures; enrich the CBOM to classify any that are genuine algorithms

## Executive summary

This assessment covers **4 cryptographic asset(s)** and raised **4 finding(s)**.

Findings by severity: critical 1, high 1, info 2.

Harvest-now-decrypt-later (HNDL) exposure: **1 asset(s)**.

### Top risks

| Asset | Quantum status | HNDL | Score |
|---|---|---|---|
| RSA-2048 | shor_broken | yes | 0.95 |
| SHA-1 | classically_broken | no | 0.60 |
| AES-256-GCM | quantum_resistant | no | 0.28 |
| TLS 1.3 | unknown | no | 0.25 |

### Mosca exposure by scenario

| Scenario | Years until CRQC | Exposed assets | HNDL assets |
|---|---|---|---|
| central | 8 | 1 | 1 |
| pessimistic | 5 | 1 | 1 |

## Inventory

**By asset type**

| | Count |
|---|---|
| algorithm | 3 |
| protocol | 1 |

**By quantum status**

| | Count |
|---|---|
| classically_broken | 1 |
| quantum_resistant | 1 |
| shor_broken | 1 |
| unknown | 1 |

**By evidence confidence**

| | Count |
|---|---|
| C1 | 1 |
| C2 | 1 |
| C3 | 1 |
| C4 | 1 |

**By system**

| | Count |
|---|---|
| (unlinked) | 2 |
| web | 2 |

## Findings

Grouped by type; 4 finding(s) in total.

| Severity | Finding | Assets | Affected |
|---|---|---|---|
| critical | Key establishment broken by Shor's algorithm (harvest-now-decrypt-later) | 1 | RSA-2048 |
| high | Algorithm already broken by classical cryptanalysis | 1 | SHA-1 |
| info | Quantum-resistant algorithm in use | 1 | AES-256-GCM |
| info | Cryptographic asset could not be classified | 1 | TLS 1.3 |

## Per-system view

### Web Tier (crown jewel)

Criticality: critical. Assets: 2. Worst score: 0.95.

Findings: critical 1, info 1.

## Remediation roadmap

### CRITICAL — Replace Shor-vulnerable public-key cryptography with NIST post-quantum standards.

Plan migration of key establishment to ML-KEM (FIPS 203) and signatures to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205), prioritising systems that protect long-lived data or perform key establishment over untrusted networks. Hybrid (classical + PQC) deployment is a common transitional step. 

Applies to 1 finding(s): quantum-vulnerable-key-establishment.

References: fips-203, fips-204, fips-205, nist-ir-8547.

### HIGH — Replace algorithms already broken or disallowed by classical cryptanalysis.

Retire MD5, SHA-1, single/triple DES, and RC4 in favour of current algorithms such as SHA-256/SHA-3 for hashing and AES-256 for symmetric encryption. 

Applies to 1 finding(s): classically-broken-primitive.

References: sp-800-131a.

### INFO — Record the algorithm, parameters, and OID so the asset can be classified.

Enrich the source CBOM or supply a manual register entry with the algorithm family, parameter set or key size, and OID where available. 

Applies to 1 finding(s): unclassified-crypto-asset.

References: nist-pqc.

## Affected assets (remediation detail)

The 2 algorithm(s) that need action, with where each was found.

| Severity | Algorithm | Status | Role | Occurrences | Found at |
|---|---|---|---|---|---|
| critical | RSA-2048 | shor_broken | pke | 1 |  |
| high | SHA-1 | classically_broken | hash | 1 |  |

## Appendix

### Methodology

Assets are ingested from CycloneDX 1.6 CBOMs and any manual register, deduplicated by a deterministic identity, linked to business systems and data classes from the context file, classified for quantum vulnerability using the rule pack, and scored. The Mosca inequality (X + Y > Z) compares how long data must stay secret (X, confidentiality lifetime) plus the time to migrate (Y) against the years until a cryptographically relevant quantum computer (Z), per user-supplied scenario. Harvest-now-decrypt-later (HNDL) marks Shor-broken key establishment or encryption over data that outlives Z.

### Scoring

final = (0.40*quantum_vulnerability + 0.30*mosca_exposure + 0.20*criticality + 0.10*evidence_confidence) / sum_of_weights; all terms in [0,1]

### Sources

- **shor-1997** [final]: Shor, P. W. (1997). Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer. SIAM Journal on Computing 26(5). — https://doi.org/10.1137/S0097539795293172
- **grover-1996** [final]: Grover, L. K. (1996). A fast quantum mechanical algorithm for database search. STOC '96. — https://doi.org/10.1145/237814.237866
- **nist-pqc** [final]: NIST Post-Quantum Cryptography Project — https://csrc.nist.gov/projects/post-quantum-cryptography
- **fips-203** [final]: FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) — https://doi.org/10.6028/NIST.FIPS.203
- **fips-204** [final]: FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA) — https://doi.org/10.6028/NIST.FIPS.204
- **fips-205** [final]: FIPS 205: Stateless Hash-Based Digital Signature Standard (SLH-DSA) — https://doi.org/10.6028/NIST.FIPS.205
- **sp-800-208** [final]: NIST SP 800-208: Recommendation for Stateful Hash-Based Signature Schemes — https://doi.org/10.6028/NIST.SP.800-208
- **sp-800-131a** [final]: NIST SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths — https://doi.org/10.6028/NIST.SP.800-131Ar2
- **nist-ir-8547** [draft]: NIST IR 8547 (Initial Public Draft): Transition to Post-Quantum Cryptography Standards — https://doi.org/10.6028/NIST.IR.8547.ipd
- **shattered-2017** [final]: Stevens, M. et al. (2017). The first collision for full SHA-1 (SHAttered). — https://shattered.io/
- **wang-md5-2005** [final]: Wang, X. & Yu, H. (2005). How to Break MD5 and Other Hash Functions. EUROCRYPT 2005. — https://doi.org/10.1007/11426639_2
- **rfc-7465** [final]: RFC 7465: Prohibiting RC4 Cipher Suites — https://doi.org/10.17487/RFC7465

