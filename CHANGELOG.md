# Changelog

All notable changes to SentryBench are documented here.
Format loosely follows Keep a Changelog. Versions follow SemVer (MAJOR.MINOR.PATCH).

## [0.6.1] - 2026-10-28
### Changed
- Added single-command dev workflow: 'pnpm dev' runs the Go core service and the Electron/Vite frontend together via concurrently
- Rewrote README.md as a full GitHub-facing doc: features table, prerequisites, quick start, manual setup, scripts reference, project structure, design principles, collapsible feature deep-dives
- Synced root package.json version with VERSION; it had drifted since early scaffolding

## [0.6.0] - 2026-10-25
### Changed
- Embedded Browser (Browser screen): isolated per-tab login sessions for logging in as multiple accounts on the same site, each tab its own in-memory cookie jar + its own capture proxy on its own port
- Per-tab HTTPS interception auto-trusts the app's own local MITM CA, scoped to that one throwaway tab partition only — no OS trust store changes, no effect on any other session
- 'Capture identity' flow: scans a tab's captured traffic for Authorization headers, API-key-shaped headers, and session cookies, surfaces them as editable candidates, saves nothing until the user confirms
- Backend: captured_requests gained a tab_id column; proxy can bind an ephemeral port and tag its captures; new /workspaces/{id}/browser-tabs and /browser-tabs/{tabId}/suggested-identity endpoints

## [0.5.0] - 2026-10-25
### Changed
- Redesigned navigation: sidebar grouped into Workspace/Tools sections with icons (lucide-react), active-item accent bar, brand mark
- Added a persistent topbar on every page showing the current page title and a workspace switcher dropdown — switching workspaces no longer requires visiting the Workspaces page
- Added shared EmptyState component; replaced plain 'select a workspace' text with icon + description + CTA across Traffic, Replay, Identities, Findings
- Added loading states to Traffic, Replay, Identities, Findings lists so they no longer flash an empty state before the first fetch resolves
- Workspaces page: icons on quick-link tiles, proper empty state for zero workspaces, active-workspace checkmark on cards
- Consistent page-header icons (matching sidebar icons) added to Traffic, Replay, Identities, Findings, JWT Inspector, Decompression Inspector, Settings; brand mark added to Login screen

## [0.4.0] - 2026-10-24
### Changed
- HTTPS MITM interception (M1 complete): local root CA (core/internal/capture/ca.go), per-host leaf cert signing, TLS termination in the proxy, CA cert download + trust-it-yourself flow in Traffic UI, HTTPS-intercept toggle
- HAR 1.2 export/import (core/internal/capture/har.go): download captured traffic as .har, import .har files from other tools, wired into Traffic UI
- Multi-identity comparison UI (M3 complete): Replay screen can send a saved request as several identities at once, compare status/size/timing, flag same-ish responses as an authorization-review signal
- Scans now run asynchronously in the background instead of blocking the HTTP request; frontend polls scan status
- Fixed MSI upgradeCode: replaced placeholder with a genuinely random GUID, added scripts/generate-msi-guid.sh for forking this project
- Added CI workflow (go build/vet + tsc typecheck on every push) to catch compile errors this project has never actually hit, since no toolchain was available while writing it

## [0.3.1] - 2026-10-24
### Changed
- Fixed packaged-app data dir: core service now writes SQLite DB + session key to app.getPath('userData') via SENTRYBENCH_DATA_DIR instead of a read-only install directory
- Fixed packaged-app version lookup: VERSION/CHANGELOG.md now bundled as extraResources next to the core binary, read via SENTRYBENCH_RESOURCES_DIR, so Settings keeps showing live version info after packaging
- Added .msi target (Windows) alongside .dmg (macOS) in electron-builder config
- Fixed release workflow: core build output dirs renamed to match electron-builder's ${os}-${arch} macro (mac/win/linux, not darwin/win32), added chmod +x on mac/linux binaries after artifact download
- Electron main process now waits for the core service's /health before showing the window, with a 5s timeout fallback

## [0.3.0] - 2026-10-24
### Changed
- Scan check framework (M6): missing security headers, permissive CORS, verbose error disclosure, sensitive data in URL, weak cookie flags, JWT alg=none, server version disclosure — passive, no exploitation
- Scans & Findings UI: run scan over traffic/requests/both, severity-sorted findings list, scan history
- Reporting/export (M7): JSON, CSV, and self-contained HTML report generation + download
- Packaging & auto-update (M8): electron-builder config for macOS (notarized)/Windows (signed NSIS)/Linux (AppImage/deb), GitHub Actions release workflow building core per-platform, electron-updater wired into main process + Settings UI

## [0.2.0] - 2026-10-23
### Changed
- JWT Inspector: decode, claims/expiry display, HMAC/RSA/ECDSA verification, weak-secret dictionary check
- Decompression Inspector: base64/base64url/hex/url decode, gzip/deflate/zlib/brotli/zstd, JSON pretty/minify, chained transforms, auto-detect
- Identity vault: per-workspace identities (bearer/apiKey/cookie/basic/custom), CRUD UI
- Replay workspace: Postman-style saved requests, send via identity, curl/PowerShell/Python/JS snippet generation
- Traffic capture: local HTTP proxy with full capture, HTTPS CONNECT passthrough, start/stop controls, traffic list + detail view
- New Go packages: jwtutil, decompression, replay, capture; SQLite tables for identities, saved_requests, captured_requests

## [0.1.0] - 2026-10-22
### Added
- Initial project scaffold (Electron + React + TypeScript desktop shell, Go core service).
- Local auth: user registration/login with bcrypt password hashing + JWT sessions.
- User profile model (display name, email, avatar color).
- Workspace model (Postman-style): multiple workspaces per user, switchable in UI.
- `/health` and `/version` endpoints on the Go core service; Settings screen renders
  live version + latest changelog entry pulled from the core service.
- SQLite storage layer (users, workspaces).
- `scripts/bump-version.sh` to bump VERSION and prepend a CHANGELOG entry in one step,
  so every update shown in Settings traces back to an actual changelog record.
