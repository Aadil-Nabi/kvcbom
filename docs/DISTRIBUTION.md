# Distribution: sharing kvcbom as a prebuilt binary

How to hand `kvcbom` to someone **without sharing the source** and **without requiring them to
install Go or any dependency**. The tool builds with `CGO_ENABLED=0 -trimpath`, so each build
is a single, fully static executable: rule packs, schemas, and templates are embedded, and the
recipient needs nothing but the one file and a terminal.

This is a release/packaging guide. For how to *run* the tool, hand recipients
[`RUNBOOK.md`](RUNBOOK.md).

---

## What the recipient needs

- **Nothing to install.** No Go, no C runtime, no DLLs, no side-car data files.
- A terminal (cmd/PowerShell, Terminal.app, or a shell). `kvcbom` is a CLI — it takes
  arguments; double-clicking it just flashes a window.
- The default PDF engine (`--pdf-engine purego`) is fully offline. Only the optional
  `--pdf-engine chromium` would need a browser on their machine, so the default keeps them
  dependency-free.

---

## One binary per platform

A compiled binary is specific to an operating system **and** CPU architecture. There is no
single file that runs everywhere, and there is **no `.sh`** to share — a shell script is not the
program. The macOS/Linux equivalent of `kvcbom.exe` is a binary simply named `kvcbom`.

| Target | Arch | Binary name | Archive (GoReleaser) |
|---|---|---|---|
| Windows | amd64 | `kvcbom.exe` | `kvcbom_<ver>_windows_amd64.zip` |
| macOS (Apple Silicon) | arm64 | `kvcbom` | `kvcbom_<ver>_darwin_arm64.tar.gz` |
| macOS (Intel) | amd64 | `kvcbom` | `kvcbom_<ver>_darwin_amd64.tar.gz` |
| Linux | amd64 | `kvcbom` | `kvcbom_<ver>_linux_amd64.tar.gz` |
| Linux | arm64 | `kvcbom` | `kvcbom_<ver>_linux_arm64.tar.gz` |

(Windows/arm64 is intentionally not built.)

---

## Build the artifacts

### Option A — GoReleaser (recommended)

Produces every platform archive at once, plus `checksums.txt`, a CycloneDX SBOM of the tool,
and a keyless cosign signature over the checksums.

```cmd
make snapshot          :: local build of all platforms into .\dist\  (no git tag needed)
```

For a real, versioned release, tag the commit and run GoReleaser proper (CI does this):

```sh
git tag v0.1.0
goreleaser release --clean
```

Notes:
- `make snapshot` runs the pre-build hooks (`go mod tidy`, `go test ./...`) and writes archives
  to `.\dist\`. The SBOM and cosign signing steps run on a **tagged release**, not a snapshot
  (they need `syft` and `cosign` present, and cosign expects an OIDC-enabled CI).
- Each archive bundles `README.md`, `CHANGELOG.md`, `LICENSE`, and `docs/**` alongside the
  binary — so the recipient gets the runbook in the box.

### Option B — one target by hand

Cross-compile from your Windows machine (only *you* need Go; the target machine needs nothing).
In `cmd.exe`:

```cmd
set CGO_ENABLED=0

set GOOS=windows& set GOARCH=amd64& go build -trimpath -o dist\windows-amd64\kvcbom.exe .\cmd\kvcbom
set GOOS=darwin&  set GOARCH=arm64& go build -trimpath -o dist\darwin-arm64\kvcbom      .\cmd\kvcbom
set GOOS=darwin&  set GOARCH=amd64& go build -trimpath -o dist\darwin-amd64\kvcbom      .\cmd\kvcbom
set GOOS=linux&   set GOARCH=amd64& go build -trimpath -o dist\linux-amd64\kvcbom       .\cmd\kvcbom
set GOOS=linux&   set GOARCH=arm64& go build -trimpath -o dist\linux-arm64\kvcbom       .\cmd\kvcbom
```

The manual route skips the version stamp; `kvcbom version` will read `dev`. Use `make build`
(or GoReleaser) when you want the version/commit/date baked in.

---

## Deliver it

- **Do not email the `.exe`** — mail gateways strip executable attachments. Zip it, or better,
  share the GoReleaser archive.
- Use a file share, an internal artifact store, or a **private GitHub release** (keeps the repo
  private while attaching downloadable binaries).
- Send the matching archive for the recipient's OS/arch, plus `checksums.txt` so they can
  verify the download (below).

---

## First-run OS prompts (tell recipients this)

An unsigned binary downloaded from outside the machine triggers an OS safety prompt the first
time. This is expected; it is not a problem with the tool.

**Windows** — SmartScreen shows "Windows protected your PC":
1. Click **More info**.
2. Click **Run anyway**.

(Some antivirus may quarantine an unknown `.exe`; an allow-list entry may be needed.)

**macOS** — Gatekeeper: "cannot be opened because the developer cannot be verified." Either:
```sh
xattr -d com.apple.quarantine ./kvcbom     # clear the download quarantine flag
chmod +x ./kvcbom
./kvcbom version
```
…or right-click the binary in Finder → **Open** → **Open** once.

**Linux** — just make it executable:
```sh
chmod +x ./kvcbom
./kvcbom version
```

---

## Verify integrity (recipient side)

Confirm the download was not altered in transit.

**Checksum (always available):**

```cmd
:: Windows
certutil -hashfile kvcbom.exe SHA256
```
```sh
# macOS / Linux
shasum -a 256 kvcbom
```

Compare the printed hash against the matching line in `checksums.txt`.

**Cosign signature (tagged releases):** `checksums.txt` is signed keyless with cosign. Anyone
with `cosign` can verify provenance against the release workflow identity:

```sh
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature   checksums.txt.sig \
  --certificate-identity-regexp '.*' \
  --certificate-oidc-issuer-regexp '.*' \
  checksums.txt
```

> This proves **integrity and provenance** (the file came from your release and was not
> tampered with). It does **not** remove the SmartScreen/Gatekeeper prompt — that is OS-level
> code signing, which is separate (below).

---

## Removing the warnings for external users (optional)

The cosign signing above is supply-chain signing, not OS code signing. To make the binary
launch cleanly for customers (no "unknown publisher" prompt), add:

- **Windows:** Authenticode code signing with a code-signing certificate (OV or EV). An EV cert
  also earns SmartScreen reputation fastest.
- **macOS:** sign with an **Apple Developer ID** certificate and **notarize** the binary with
  Apple, then staple the ticket.

Neither is wired into `.goreleaser.yaml` yet; both can be added there (GoReleaser supports a
Windows `sign` step and a macOS notarization step). For internal or trusted recipients, the
one-time "Run anyway" / right-click-Open step is usually acceptable and needs no certificates.

---

## Keeping it closed-source

Sharing the binary does not share the source — the repo stays private. Be aware, though, that a
compiled binary is still inspectable: `strings`, symbol names, and embedded assets can be read,
and `-trimpath`/`-s -w` only strip paths and the symbol table, not the logic. That is fine for
distribution; it is not an obfuscation or secret-protection guarantee. Do not embed secrets in
the binary.

---

## Quick note to paste to a recipient

> You've been sent `kvcbom` for <Windows/macOS/Linux>. No installation is needed — it's a
> single self-contained program.
> - **Windows:** unzip, then in a terminal run `kvcbom.exe version`. If Windows shows a blue
>   "protected your PC" box, click *More info → Run anyway*.
> - **macOS:** untar, then `xattr -d com.apple.quarantine ./kvcbom && chmod +x ./kvcbom`, then
>   `./kvcbom version`.
> - **Linux:** untar, then `chmod +x ./kvcbom && ./kvcbom version`.
>
> See `docs/RUNBOOK.md` (included in the archive) for how to generate a report.

---

## Reference

- [`RUNBOOK.md`](RUNBOOK.md) — how to run the tool once it's on the machine.
- [`USAGE.md`](USAGE.md) — every command and flag.
- `.goreleaser.yaml` — the release build definition (platforms, archives, checksums, SBOM, signing).
