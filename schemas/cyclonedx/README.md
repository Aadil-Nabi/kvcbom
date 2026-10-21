# Embedded CycloneDX schemas

These JSON Schema documents are bundled so CBOM validation runs fully offline.

| File | Source | Version |
|------|--------|---------|
| `bom-1.6.schema.json` | https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json | CycloneDX 1.6 |
| `bom-1.7.schema.json` | https://github.com/CycloneDX/specification/blob/1.7/schema/bom-1.7.schema.json | CycloneDX 1.7 |
| `cryptography-defs.schema.json` | https://github.com/CycloneDX/specification/blob/1.7/schema/cryptography-defs.schema.json | crypto-asset definitions, referenced by bom-1.7 |
| `spdx.schema.json` | https://github.com/CycloneDX/specification/blob/1.6/schema/spdx.schema.json | referenced by bom-1.6 and bom-1.7 |
| `jsf-0.82.schema.json` | https://github.com/CycloneDX/specification/blob/1.6/schema/jsf-0.82.schema.json | JSON Signature Format 0.82, referenced by bom-1.6 and bom-1.7 |

Each uses `$id` under `http://cyclonedx.org/schema/…`; the bom schema references the
other two by relative path, which resolves against that base once all three are
registered with the schema compiler.

**Licence:** the CycloneDX specification and its schemas are published by the CycloneDX
project under Apache-2.0. Retain this notice if redistributing.

To refresh: re-download the three files from the `1.6` branch of the specification repo
and keep the `$id` values unchanged.
