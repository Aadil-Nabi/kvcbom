# Regulator overlay fill-in checklist

The regulator/framework packs ship **structure-only**: the finding-type → control mappings are
in place, but every `control_id`, `control_title`, and source `url` is a `TODO(source):`
placeholder. This document is the checklist a compliance reviewer uses to turn an overlay into a
verified, customer-presentable mapping.

> **Rule:** never invent a control identifier, requirement text, date, or URL. Copy each value
> from the official document and record where it came from. Until an overlay is verified, every
> report that uses it shows an "unverified content" warning — that is intentional.

## Where overlays live

`rulepacks/<id>.yaml` (embedded in the binary). Editing a file and rebuilding re-embeds it;
or point `--framework ./path/to/overlay.yaml` at a working copy while drafting.

## What to fill in each overlay

For the pack's `sources` entry (the regulator document):

- `url` — the canonical URL (prefer a DOI or the official download page).
- `title` — the exact document title and version/edition.
- `status` — `final` once it cites a published (non-draft) document; `draft` while the source
  itself is a draft; `vendor` for non-governmental guidance.
- `retrieved_date` — the date you verified it.

For each entry under `framework.mappings`:

- `control_id` — the official clause / requirement / milestone identifier.
- `control_title` — the official requirement text (or a faithful short quote).
- `source` — leave pointing at the `sources` id (already wired).

Then:

1. `kvcbom rulepacks validate <id|path>` — must report **0 errors and 0 warnings** (no remaining
   `TODO(source)` markers).
2. Change the pack's top-level `status:` to `final` (from `draft`/`vendor`).
3. Bump the pack `version:` (semver) and record the change in `CHANGELOG.md`.
4. Re-run a sample report; confirm the "unverified content" warning for that framework is gone.

## Canonical finding types to map

Each overlay maps these (emitted by the `baseline-pqc` classifier):

| finding type | what the control should address |
|---|---|
| `quantum-vulnerable-key-establishment` | Shor-broken key exchange / public-key encryption (RSA, DH, ECDH) — harvest-now-decrypt-later |
| `quantum-vulnerable-signature` | Shor-broken signatures (RSA, ECDSA, EdDSA, DSA) — forgery risk |
| `classically-broken-primitive` | already-disallowed algorithms (MD5, SHA-1, 3DES, RC4) |
| `symmetric-strength-reduced` | Grover-weakened symmetric ciphers (e.g. AES-128) |

---

## Per-pack sources

For each regulator below, confirm the exact title/URL/clauses against the live document — the
descriptions here say *what to look for*, not verified citations.

### `nist-ir-8547` — NIST IR 8547 (US)

- **Document:** *NIST IR 8547, Transition to Post-Quantum Cryptography Standards.* The repo stub
  already points at the Initial Public Draft (`https://doi.org/10.6028/NIST.IR.8547.ipd`).
  **When the final is published, update the URL and set `status: final`.**
- **Fill from:** the transition-timeline tables that list each quantum-vulnerable family and its
  **deprecation** and **disallowance** years. Map:
  - key-establishment → the RSA/DH/ECDH key-establishment transition row(s).
  - signature → the RSA/ECDSA/EdDSA signature transition row(s).
  - classically-broken → the reference to NIST SP 800-131A disallowances.
  - symmetric-strength-reduced → the guidance on 128-bit-strength symmetric algorithms.
- Record the exact table/section number as `control_id` and the milestone wording as
  `control_title`. (The draft proposes dates around 2030/2035 — do not hard-code these until
  confirmed against the published edition.)

### `cnsa-2.0` — NSA CNSA 2.0 (US national security systems)

- **Document:** *NSA Commercial National Security Algorithm Suite 2.0* advisory and its FAQ
  (published on media.defense.gov). **Confirm the exact URL.**
- **Fill from:** the CNSA 2.0 approved-algorithm table and adoption-timeline table. Map:
  - key-establishment → the requirement to use ML-KEM (and the timeline for the relevant product
    class: software/firmware signing, networking, etc.).
  - signature → the requirement to use ML-DSA / LMS / XMSS as applicable.
  - symmetric-strength-reduced → the AES-256 requirement.
  - classically-broken → the requirement retiring SHA-1 / legacy hashes (SHA-384/512 only).
- CNSA 2.0 adoption dates differ by product category — capture the category in `control_title`.

### `csa-qri-sg` — Cyber Security Agency of Singapore

- **Document:** the official CSA Singapore quantum-readiness / PQC transition guidance.
  **Confirm the exact title and URL** (CSA publishes advisories and guidelines; pick the
  authoritative one your customer is being assessed against).
- **Fill from:** the guidance's objectives/controls for inventorying and migrating
  quantum-vulnerable cryptography. Map each finding type to the corresponding objective.
- Status stays `vendor` unless the document is a government standard, in which case `final`.

### `enisa-eu` — ENISA (European Union)

- **Document:** the relevant ENISA post-quantum publication(s), e.g. *Post-Quantum Cryptography:
  Current state and quantum mitigation* and the PQC integration study. **Confirm titles/URLs.**
- **Fill from:** ENISA's recommendations on migrating key establishment and signatures, retiring
  broken primitives, and symmetric key sizes. ENISA guidance is advisory (recommendations, not
  numbered controls) — use the section heading as `control_id` and the recommendation as
  `control_title`.

### `uk-ncsc` — UK National Cyber Security Centre

- **Document:** NCSC post-quantum migration guidance (e.g. *Next steps in preparing for
  post-quantum cryptography* / the PQC migration guidance with its milestone years).
  **Confirm titles/URLs.**
- **Fill from:** the NCSC migration milestones (discovery → priority migration → completion) and
  map the key-establishment and signature finding types to the relevant milestone, and the
  broken/weak primitives to the corresponding guidance.

---

## Adding another regulator

Copy an existing overlay (e.g. `enisa-eu.yaml`), change `id`, `name`, `description`, the `sources`
entry, and the `framework.id`/`name`, keep the four `finding_type` mappings, and fill the controls
from that body's document. `kvcbom rulepacks list` will show it; validate and flip to `final` the
same way. No code change is needed — overlays are pure content.
