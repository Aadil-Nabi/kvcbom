# testdata

Fixtures used by the engine's unit, golden, and fuzz tests live **next to the package that
uses them**, under `pkg/.../testdata/`. They are all hand-written for this project (no
third-party sample was vendored into those), so they carry no external licence.

This top-level directory holds larger, real-world-shaped sample CBOMs used for manual and
integration smoke testing (for example, `kvcbom report --cbom testdata/<file>`). They are not
consumed by `go test`.

> **Provenance:** confirm the source and licence of any sample placed here before redistributing
> it. If a sample originates from a public project (e.g. the PQCA CBOMkit samples), record its
> source URL and licence in this file.
