# SentryBench

Cross-platform desktop workbench for **authorized** API security testing —
traffic capture, Postman-style request replay, multi-identity authorization
testing, a JWT inspector, and a decompression/encoding inspector.

> **Authorization required.** Only use SentryBench against systems you own or
> have explicit written permission to test. The app enforces safe mode, a
> target allowlist, and confirmation prompts for destructive requests, but
> the legal and ethical responsibility is yours.

## Stack

- **Desktop UI:** Electron + React + TypeScript (Vite), Zustand for state, Tailwind CSS.
- **Core service:** Go (`core/`) — HTTP API consumed by the Electron app over localhost.
- **Storage:** SQLite (`modernc.org/sqlite`), with secrets destined for the OS keychain.
- **Auth:** bcrypt password hashing + JWT sessions, local accounts (no cloud).

This repo currently implements **Milestones 0–5** of the full implementation plan
(`docs/implementation-plan.md` if you add it):

- **M0** — project scaffold, versioning, CI-ready layout.
- **Login/profiles/workspaces** — accounts, bcrypt+JWT sessions, Postman-style workspaces.
- **M1** — local proxy with full HTTP capture, plus HTTPS interception via a locally-generated
  root CA (`core/internal/capture/ca.go`): the proxy terminates TLS with a per-host leaf cert
  signed by that CA, decrypts and records the request/response, then re-encrypts on to the
  real destination. Only decrypts traffic from clients that have both been pointed at the
  proxy *and* explicitly trust `ca-cert.pem` (download button on the Traffic screen) — nothing
  silent. Falls back to plain CONNECT passthrough (uninspected) if the "Intercept HTTPS"
  toggle is off or a host is excluded. HAR 1.2 export/import (`core/internal/capture/har.go`)
  round-trips captured traffic with browser devtools and other tooling.
- **M2** — Postman-style replay workspace: saved requests, send, curl/PowerShell/Python/JS snippets.
- **M3** — identity vault (bearer/apiKey/cookie/basic/custom), per-identity request sending, and
  a multi-identity comparison view (Replay screen → "Compare across identities"): send the same
  request as several identities at once and see status/size/timing side by side, with a
  same-ish-response flag as a starting signal for IDOR/privilege-escalation review — it flags,
  it doesn't claim to have confirmed anything.
- **M4** — JWT Inspector: decode, claims/expiry, HMAC/RSA/ECDSA verification, weak-secret check.
- **M5** — Decompression Inspector: base64/base64url/hex/url decode, gzip/deflate/zlib/brotli/zstd,
  JSON pretty/minify, chained transforms, auto-detect.

- **M6** — scan check framework (`core/internal/scan`): passive, non-exploiting checks
  (missing security headers, permissive CORS, verbose error disclosure, sensitive data
  in URLs, weak cookie flags, JWT alg=none, server version disclosure) run over
  captured traffic and/or saved requests, in the background (`go s.runScan(...)` — the
  HTTP request that starts a scan returns immediately with `status: "running"`; the UI
  polls until it completes rather than blocking on potentially many live requests).
  Findings persist per-scan; `Findings.tsx` shows them with severity badges and lets
  you re-run and compare scans.
- **M7** — reporting/export (`core/internal/report`): JSON, CSV, and a self-contained
  HTML report, downloadable from the Findings screen. SARIF/PDF are not yet implemented
  — same `Data -> []byte` shape, just another `Generate*` function.
- **M8** — packaging/signing/auto-update: `apps/desktop/package.json`'s `build` block
  configures electron-builder for macOS (notarized, hardened runtime), Windows
  (Authenticode-signed NSIS installer), and Linux (AppImage/deb).
  `.github/workflows/release.yml` builds the Go core for each platform, embeds it as
  an Electron extraResource, then builds/signs/publishes via electron-builder's GitHub
  provider. `electron-updater` is wired into `electron/main.ts`: on launch it checks
  the latest GitHub release, and `Settings.tsx` shows a "download / restart & install"
  prompt when one's available — a different signal from the version/changelog panel
  above it, which always reflects *this* build's own `VERSION`/`CHANGELOG.md`, not
  whether a newer one exists.

Not yet built: SARIF/PDF report formats (same `Data -> []byte` shape as JSON/CSV/HTML,
just not written yet), and a real job queue for scans (the background goroutine works
fine for one scan at a time — concurrent scans on the same workspace would race on
findings insertion order, not on correctness, but it's not something to lean on yet).

This repo has a CI workflow (`.github/workflows/ci.yml`) that `go build`/`go vet`s the
core and typechecks the desktop app on every push — but as of this writing it has
never actually been *run*: everything here was written without a Go or Node toolchain
available to compile it. Treat the first CI run as the real first compile check, not
this description.

See `scripts/bump-version.sh`'s own output after a bump for the exact commands
to cut a signed release (tag off `VERSION`, push, let the workflow do the rest).

## Embedded Browser (multi-identity login capture)

The Browser screen (`apps/desktop/src/pages/Browser.tsx`) is for a specific workflow:
log in as several different accounts on the same site, each in its own isolated tab,
and turn each login into an Identity without copy-pasting tokens by hand.

- Each tab is an Electron `BrowserView` with its own **in-memory, non-persisted session
  partition** — its own cookie jar, gone the moment the tab closes. Logging into a fresh
  tab never inherits a previous tab's session.
- Each tab is also routed through its **own capture proxy**, on its own ephemeral port
  (`POST /workspaces/{id}/browser-tabs` in `core/internal/api/router.go`, backed by
  `capture.Proxy` with a `TabID`). That's what makes "this token belongs to this tab"
  precise instead of a host/timing guess.
- **HTTPS interception in these tabs trusts the app's own local MITM CA automatically**
  (`ses.setCertificateVerifyProc` in `electron/main.ts`'s `openBrowserTab`) — unlike the
  regular Traffic screen, which requires the user to manually install and trust
  `ca-cert.pem`. This is a deliberate, narrowly-scoped exception: it only affects that
  one throwaway, in-memory tab partition; it never touches the OS trust store, the app's
  own session, or any other tab; and the proxy's outbound connection to the real site is
  still verified normally (Go's default TLS transport, real root CAs) — only the
  proxy-to-this-tab leg, which is our own intentional MITM, skips the manual-trust step
  that exists for the general-purpose capture proxy.
- "Capture identity" (`GET /browser-tabs/{tabId}/suggested-identity`) scans that tab's
  captured traffic for an `Authorization` header, API-key-shaped custom headers, and
  session-looking cookies, and returns them as **candidates only** — nothing is saved as
  an Identity until the user reviews and confirms each one in the modal.

## Packaging into .dmg / .msi

Building the desktop app into an installer isn't just "run electron-builder" —
the Go core service has to actually work once it's bundled, which means two
things dev mode doesn't need to care about:

1. **Where `VERSION`/`CHANGELOG.md` live.** In dev, `go run ./cmd/workbench`
   finds them by walking up from the repo checkout. A packaged app has no
   checkout, so `package.json`'s `build.extraResources` copies both files
   into the same `core/` resource folder as the binary, and
   `electron/main.ts` passes that folder to the binary as
   `SENTRYBENCH_RESOURCES_DIR`. Settings' version panel reads from there —
   this is what makes "shows the right version after an update" keep working
   post-packaging, not just in dev.
2. **Where the SQLite DB lives.** A signed/notarized `.app` or installed
   `.msi` directory is read-only. The core service can't write its database
   or session key next to itself anymore, so `main.ts` passes
   `app.getPath("userData")` as `SENTRYBENCH_DATA_DIR`, and the Go binary
   writes there instead. (`core/internal/database`'s `Open()` doesn't change —
   it just gets handed a different, writable path.)

`electron/main.ts` also waits (up to 5s) for the core service's `/health` to
respond before showing the window, and sets both env vars every time it
spawns the binary — see `startCoreService()` and `waitForCore()`.

**Building:**

```bash
pnpm install
pnpm build:desktop        # builds core for the host OS/arch, then electron-builder
```

- **macOS → `.dmg`**: `mac.target` includes `dmg`. Needs `CSC_LINK` (a
  base64 `.p12`) + `CSC_KEY_PASSWORD`, and `APPLE_ID` /
  `APPLE_APP_SPECIFIC_PASSWORD` / `APPLE_TEAM_ID` for notarization
  (`mac.notarize: true`). Unsigned local builds work too — Gatekeeper will
  just warn on first launch.
- **Windows → `.msi`**: `win.target` is `["msi", "nsis"]`, so you get both an
  MSI and an NSIS installer. The `msi.upgradeCode` in `package.json` is a
  **placeholder GUID** — generate your own
  (`[guid]::NewGuid()` in PowerShell) and keep it constant across every
  release, or Windows will treat each version as an unrelated product
  instead of an in-place upgrade. Needs `WIN_CSC_LINK` +
  `WIN_CSC_KEY_PASSWORD` for Authenticode signing (optional for local/dev
  builds, strongly recommended for anything you distribute — unsigned EXEs
  / MSIs get a SmartScreen warning).
- **Linux → AppImage/deb**: no signing required.

`.github/workflows/release.yml` does this for all three platforms on every
`vX.Y.Z` tag: builds `core` per OS/arch into `core/dist/<os>-<arch>/`
(directory names **must** match electron-builder's own `${os}-${arch}`
macro — `mac`/`win`/`linux`, not `darwin`/`win32` — that's what
`extraResources` pulls from), uploads each as a build artifact, downloads
and normalizes them on the desktop-build job, then runs electron-builder
with `--publish always` to cut a GitHub release carrying the `.dmg`, `.msi`,
`.exe`, `.AppImage`, and `.deb`.

## Versioning & changelog (shows up in Settings)

- `VERSION` at repo root is the single source of truth (SemVer).
- `CHANGELOG.md` holds one entry per version, newest first.
- The Go core service exposes `GET /version`, returning the current version **and**
  the matching changelog entry, parsed straight from `CHANGELOG.md`.
- The Settings screen in the desktop app calls `/version` and renders both — so after
  any update, the user sees the new version number and exactly what changed, with
  no manual UI edits required.
- To cut a release: `./scripts/bump-version.sh patch "Fixed JWT expiry parsing"`
  (or `minor` / `major`). This bumps `VERSION` and prepends a dated `CHANGELOG.md`
  section in one step, so the two files never drift apart.

## Getting started

```bash
# Core service
cd core
go mod tidy
go run ./cmd/workbench

# Desktop app (separate terminal)
cd apps/desktop
pnpm install
pnpm dev
```

The Electron app's dev server calls the Go service's `/health` and `/version`
endpoints on boot; the Dashboard shows both as a connectivity check.

## Repository layout

```text
sentrybench/
├── VERSION
├── CHANGELOG.md
├── scripts/bump-version.sh
├── core/                     # Go service
│   ├── cmd/workbench/main.go
│   └── internal/
│       ├── version/          # reads VERSION + CHANGELOG.md
│       ├── database/         # SQLite setup + migrations
│       ├── auth/              # bcrypt + JWT sessions
│       ├── models/           # User, Workspace, Identity, SavedRequest, CapturedRequest...
│       ├── capture/          # local proxy (HTTP capture, HTTPS CONNECT passthrough)
│       ├── replay/           # request execution + curl/PowerShell/Python/JS snippets
│       ├── jwtutil/          # JWT decode/verify/weak-secret check
│       ├── decompression/    # gzip/deflate/zlib/brotli/zstd/base64/hex/url + chains
│       └── api/              # HTTP router wiring all of the above
└── apps/desktop/             # Electron + React + TypeScript
    ├── electron/main.ts
    ├── electron/preload.ts
    └── src/
        ├── lib/coreClient.ts      # typed fetch client for the Go API
        ├── stores/authStore.ts
        └── pages/
            ├── Login.tsx
            ├── Workspaces.tsx
            ├── Traffic.tsx        # proxy controls + captured request list
            ├── Replay.tsx         # Postman-style request editor
            ├── Identities.tsx     # identity vault
            ├── JwtInspector.tsx
            ├── DecompressionInspector.tsx
            └── Settings.tsx
```
