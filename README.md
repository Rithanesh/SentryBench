# SentryBench

**SentryBench** is a cross-platform desktop workbench for **authorized** API
security testing — traffic capture (including HTTPS interception), an
embedded multi-account browser for pulling login tokens, Postman-style
request replay, a multi-identity authorization-testing comparison view, a
JWT inspector, a decompression/encoding inspector, and a passive
vulnerability scan-and-report pipeline.

It's an Electron desktop app (React + TypeScript) backed by a local Go HTTP
service, with SQLite for storage. No cloud, no telemetry — everything runs
on your machine.

> ⚠️ **Authorization required.** Only point SentryBench at systems you own
> or have explicit written permission to test. The app is built to be a
> passive observer and require explicit confirmation for anything
> sensitive (see [Design principles](#design-principles) below), but the
> legal and ethical responsibility for how you use it is yours.

---

## Table of contents

- [Features](#features)
- [Tech stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Quick start (single command)](#quick-start-single-command)
- [Manual setup](#manual-setup)
  - [1. Backend (Go core service)](#1-backend-go-core-service)
  - [2. Frontend (Electron + React desktop app)](#2-frontend-electron--react-desktop-app)
- [Available scripts](#available-scripts)
- [Project structure](#project-structure)
- [Design principles](#design-principles)
- [Feature deep dives](#feature-deep-dives)
- [Versioning & changelog](#versioning--changelog)
- [Packaging into .dmg / .msi](#packaging-into-dmg--msi)
- [Project status](#project-status)

---

## Features

| Area | What it does |
|---|---|
| **Traffic capture** | Local proxy with full HTTP capture, plus HTTPS interception via a locally-generated root CA you explicitly install and trust |
| **Embedded Browser** | Isolated per-tab login sessions — log in as multiple accounts on the same site, each in its own cookie jar, and auto-suggest tokens to save as Identities |
| **Replay** | Postman-style saved requests: build, send, and export as curl / PowerShell / Python / JavaScript |
| **Identity vault** | Store bearer tokens, API keys, cookies, and basic-auth credentials per workspace |
| **Multi-identity comparison** | Send one request as several identities at once and compare status/size/timing — a starting signal for authorization bugs (IDOR, privilege escalation) |
| **JWT Inspector** | Decode, inspect claims/expiry, verify HMAC/RSA/ECDSA signatures, run a weak-secret dictionary check |
| **Decompression Inspector** | Chainable base64/base64url/hex/URL decode, gzip/deflate/zlib/brotli/zstd decompression, JSON pretty-print |
| **Scans & findings** | Passive, non-exploiting checks (missing security headers, permissive CORS, verbose errors, sensitive data in URLs, weak cookie flags, JWT `alg=none`, version disclosure) over captured traffic or saved requests |
| **Reporting** | Export findings as JSON, CSV, or a self-contained HTML report |
| **HAR import/export** | Round-trip captured traffic with browser devtools and other tooling |
| **Workspaces** | Postman-style workspaces per project, with local accounts (bcrypt + JWT sessions) |
| **Auto-update & signed installers** | macOS (notarized `.dmg`), Windows (signed `.msi`), Linux (AppImage/deb), with `electron-updater` wired in |

## Tech stack

- **Desktop UI:** Electron, React, TypeScript, Vite, Tailwind CSS, Zustand, `lucide-react`
- **Core service:** Go — a plain HTTP API the desktop app talks to on `localhost`
- **Storage:** SQLite (`modernc.org/sqlite`, pure Go — no CGO toolchain needed)
- **Auth:** bcrypt password hashing + JWT sessions, local accounts only

---

## Prerequisites

Install these before you do anything else:

| Tool | Version | Used for |
|---|---|---|
| [Go](https://go.dev/dl/) | 1.22+ | the core backend service |
| [Node.js](https://nodejs.org/) | 20+ | the Electron/React frontend |
| [pnpm](https://pnpm.io/installation) | 9+ | package manager for the frontend (`npm install -g pnpm`) |

No database server, no Docker, no CGO compiler — SQLite is pure Go and the
frontend build has no native dependencies.

---

## Quick start (single command)

From the repo root, install everything once:

```bash
pnpm install        # installs frontend deps AND the root dev-orchestration deps
cd core && go mod tidy && cd ..   # fetches Go deps, generates go.sum
```

Then run **both** the backend and frontend together with one command:

```bash
pnpm dev
```

This uses [`concurrently`](https://www.npmjs.com/package/concurrently) to
start the Go core service (`go run ./cmd/workbench`) and the Vite dev
server + Electron app in parallel, in one terminal, with color-coded
`[core]` / `[desktop]` log prefixes. Stopping it (`Ctrl+C`) stops both.

That's it — the Electron window will open once Vite's dev server is ready,
and the app will connect to the core service on `http://127.0.0.1:4317`.

---

## Manual setup

If you'd rather run the backend and frontend in separate terminals (useful
for watching their logs independently, or restarting one without the
other), here's how.

### 1. Backend (Go core service)

```bash
cd core
go mod tidy          # first time only — fetches dependencies, writes go.sum
go run ./cmd/workbench
```

You should see:

```
sentrybench-core: data dir ..., version dir ...
sentrybench-core listening on http://127.0.0.1:4317
```

Leave this running. It serves the HTTP API the frontend talks to, and
owns the SQLite database, the local MITM CA, and the capture proxy.

**Verify it's up:**

```bash
curl http://127.0.0.1:4317/health
# {"status":"ok"}
```

### 2. Frontend (Electron + React desktop app)

In a second terminal, from the repo root:

```bash
pnpm install                     # installs all workspace packages, including apps/desktop
pnpm dev:desktop
```

This starts Vite's dev server and launches the Electron window pointed at
it, with hot reload for UI changes. The app expects the backend from step
1 to already be running on port `4317`.

---

## Available scripts

Run these from the **repo root** with `pnpm <script>`:

| Script | What it does |
|---|---|
| `pnpm dev` | Runs backend + frontend together (see [Quick start](#quick-start-single-command)) |
| `pnpm dev:core` | Runs only the Go core service (`go run ./cmd/workbench`) |
| `pnpm dev:desktop` | Runs only the Electron/Vite frontend |
| `pnpm build:desktop` | Builds the core binary for your OS/arch and packages the desktop app (`.dmg`/`.msi`/AppImage depending on platform) — see [Packaging](#packaging-into-dmg--msi) |
| `pnpm release` | Runs `scripts/bump-version.sh` — bumps `VERSION` and prepends a `CHANGELOG.md` entry in one step |

Go-specific commands (run from `core/`):

| Command | What it does |
|---|---|
| `go run ./cmd/workbench` | Run the core service directly |
| `go build ./...` | Compile-check everything without running it |
| `go vet ./...` | Static analysis / lint |
| `go test ./...` | Run tests |

---

## Project structure

```text
sentrybench/
├── package.json              # root scripts: dev, dev:core, dev:desktop, build:desktop, release
├── VERSION                   # single source of truth for the app version (SemVer)
├── CHANGELOG.md              # one entry per version, newest first
├── scripts/
│   ├── bump-version.sh       # bumps VERSION + CHANGELOG.md together
│   └── generate-msi-guid.sh  # one-time: generate your own Windows MSI upgradeCode
├── .github/workflows/
│   ├── ci.yml                 # go build/vet + tsc typecheck on every push
│   └── release.yml            # builds + signs + publishes installers on a version tag
│
├── core/                      # Go backend
│   ├── cmd/workbench/main.go  # entrypoint
│   └── internal/
│       ├── version/           # reads VERSION + CHANGELOG.md for GET /version
│       ├── database/          # SQLite setup + migrations
│       ├── auth/               # bcrypt + JWT sessions
│       ├── models/            # User, Workspace, Identity, SavedRequest, CapturedRequest, Finding, Scan...
│       ├── capture/            # proxy (HTTP capture, HTTPS MITM via local CA), HAR export/import, browser-tab proxies
│       ├── replay/             # request execution + curl/PowerShell/Python/JS snippet generation
│       ├── jwtutil/            # JWT decode/verify/weak-secret check
│       ├── decompression/      # gzip/deflate/zlib/brotli/zstd/base64/hex/url + chains
│       ├── scan/                # passive vulnerability checks
│       ├── report/              # JSON/CSV/HTML report generation
│       └── api/                 # HTTP router wiring all of the above
│
└── apps/desktop/              # Electron + React + TypeScript frontend
    ├── electron/
    │   ├── main.ts             # app lifecycle, spawns core service, BrowserView tab management, auto-update
    │   └── preload.ts          # safe IPC bridge to the renderer
    └── src/
        ├── lib/coreClient.ts   # typed fetch client for the Go API
        ├── stores/authStore.ts # Zustand session/workspace state
        ├── components/
        │   ├── EmptyState.tsx
        │   └── WorkspaceSwitcher.tsx
        └── pages/
            ├── Login.tsx
            ├── Workspaces.tsx
            ├── Traffic.tsx              # proxy controls, CA cert download, captured request list
            ├── Browser.tsx              # embedded multi-tab browser for multi-account login capture
            ├── Replay.tsx               # Postman-style request editor + identity comparison
            ├── Identities.tsx           # identity vault
            ├── Findings.tsx             # scans + findings + report export
            ├── JwtInspector.tsx
            ├── DecompressionInspector.tsx
            └── Settings.tsx             # version/changelog panel, account, auto-update prompt
```

---

## Design principles

SentryBench is built around a few deliberate constraints, worth knowing
before you dig into the code:

- **Nothing auto-exploits.** The scan suite (`core/internal/scan`) is
  entirely passive — it only reads headers/bodies that were already
  captured or returned by a request *you* chose to send. It never sends
  extra probe requests or fuzzes input.
- **Nothing auto-trusts outside its own sandbox.** HTTPS interception
  requires you to manually install and trust the generated CA certificate
  for the general-purpose Traffic proxy. The one exception — the Embedded
  Browser's per-tab sessions — auto-trusts that same CA, but *only* inside
  an isolated, in-memory, throwaway session partition that's destroyed
  when the tab closes; it never touches your OS trust store or any other
  session. See [Feature deep dives](#feature-deep-dives).
- **Nothing auto-saves credentials.** The Embedded Browser's "Capture
  identity" flow only ever *suggests* candidate tokens/cookies for you to
  review, edit, and explicitly confirm before anything is written to the
  identity vault.

---

## Feature deep dives

<details>
<summary><strong>Embedded Browser (multi-identity login capture)</strong></summary>

The Browser screen is for logging in as several different accounts on the
same site, each in its own isolated tab, and turning each login into an
Identity without copy-pasting tokens by hand.

- Each tab is an Electron `BrowserView` with its own **in-memory,
  non-persisted session partition** — its own cookie jar, gone the moment
  the tab closes. A fresh tab never inherits a previous tab's session.
- Each tab is also routed through its **own capture proxy** on its own
  ephemeral port, so which token belongs to which login is exact, not a
  host/timing guess.
- HTTPS interception in these tabs auto-trusts the app's own local MITM CA
  — scoped to that one throwaway partition only (see
  [Design principles](#design-principles)).
- "Capture identity" scans that tab's traffic for an `Authorization`
  header, API-key-shaped headers, and session-looking cookies, and returns
  them as **candidates only** — you review and confirm each one before it
  becomes an Identity.

</details>

<details>
<summary><strong>Versioning & changelog</strong></summary>

- `VERSION` at the repo root is the single source of truth (SemVer).
- `CHANGELOG.md` holds one entry per version, newest first.
- The core service exposes `GET /version`, returning the current version
  **and** the matching changelog entry, parsed straight from
  `CHANGELOG.md`.
- The Settings screen calls `/version` and renders both — so after any
  update, you see the new version number and exactly what changed, with no
  manual UI edits required.
- To cut a release: `pnpm release patch "Fixed JWT expiry parsing"` (or
  `minor` / `major`). This bumps `VERSION` and prepends a dated
  `CHANGELOG.md` section in one step, so the two files never drift apart.

</details>

---

## Packaging into .dmg / .msi

```bash
pnpm install
pnpm build:desktop        # builds the core binary for the host OS/arch, then runs electron-builder
```

- **macOS → `.dmg`**: needs `CSC_LINK` (base64 `.p12`) + `CSC_KEY_PASSWORD`,
  and `APPLE_ID` / `APPLE_APP_SPECIFIC_PASSWORD` / `APPLE_TEAM_ID` for
  notarization. Unsigned local builds work too — Gatekeeper just warns on
  first launch.
- **Windows → `.msi`**: run `scripts/generate-msi-guid.sh` **once**, right
  after forking this repo, and set the result as `build.msi.upgradeCode`
  in `apps/desktop/package.json` — then never change it again, or Windows
  will treat each release as an unrelated product instead of an in-place
  upgrade. Needs `WIN_CSC_LINK` + `WIN_CSC_KEY_PASSWORD` for Authenticode
  signing (optional locally, recommended for distribution).
- **Linux → AppImage/deb**: no signing required.

`.github/workflows/release.yml` does all three platforms automatically on
every `vX.Y.Z` tag — see the workflow file for the full pipeline (it also
embeds the Go core binary and `VERSION`/`CHANGELOG.md` as Electron
`extraResources` so the packaged app works the same as it does in dev).

---

## Project status

This repo was built incrementally and has a CI workflow
(`.github/workflows/ci.yml`) that runs `go build`/`go vet` on the core and
typechecks the frontend on every push — run that (or `go build ./...` /
`pnpm exec tsc --noEmit` locally) before relying on any given commit.
`CHANGELOG.md` has the full feature-by-feature history.

**Not yet implemented:** SARIF/PDF report formats, a real background job
queue for concurrent scans (the current one works fine for a single scan
at a time per workspace).

---

## License

Add your license of choice here before publishing.
