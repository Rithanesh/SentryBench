import { app, BrowserWindow, BrowserView, ipcMain, session as electronSession } from "electron";
import path from "node:path";
import http from "node:http";
import { spawn, ChildProcessWithoutNullStreams } from "node:child_process";
import { autoUpdater } from "electron-updater";

let coreProcess: ChildProcessWithoutNullStreams | null = null;
let mainWindow: BrowserWindow | null = null;

// --- Embedded Browser tabs -----------------------------------------------
// One BrowserView per open tab, keyed by the tab ID the core service
// assigned when it stood up that tab's own capture proxy (see
// POST /workspaces/{id}/browser-tabs in core/internal/api/router.go).
// Each tab gets an isolated, in-memory (non-"persist:") session partition —
// its own cookie jar — so logging in as a different user in a fresh tab
// never inherits a previous tab's session, and closing a tab discards it.
const browserViews = new Map<string, BrowserView>();

const isDev = !app.isPackaged;
const CORE_ADDR = "127.0.0.1:4317";

function startCoreService() {
  // In dev, assume `go run ./cmd/workbench` is started separately
  // (see README / pnpm dev:core), reading VERSION/CHANGELOG.md and writing
  // its SQLite DB straight from the repo checkout. In a packaged build
  // there is no repo checkout, so the bundled binary needs to be told
  // explicitly where to find each:
  //   - SENTRYBENCH_RESOURCES_DIR: the "core" extraResources folder, which
  //     carries VERSION + CHANGELOG.md alongside the binary (see
  //     package.json's build.extraResources) so Settings' version panel
  //     keeps working post-packaging.
  //   - SENTRYBENCH_DATA_DIR: app.getPath("userData") — the app's own
  //     install directory is read-only once signed/notarized, so the
  //     SQLite DB and session key need a separate writable location.
  if (isDev) return;

  const binaryName = process.platform === "win32" ? "sentrybench-core.exe" : "sentrybench-core";
  const resourcesDir = path.join(process.resourcesPath, "core");
  const binaryPath = path.join(resourcesDir, binaryName);

  coreProcess = spawn(binaryPath, [], {
    stdio: "pipe",
    env: {
      ...process.env,
      SENTRYBENCH_RESOURCES_DIR: resourcesDir,
      SENTRYBENCH_DATA_DIR: app.getPath("userData"),
      SENTRYBENCH_CORE_ADDR: CORE_ADDR,
    },
  });
  coreProcess.stdout.on("data", (d) => console.log(`[core] ${d}`));
  coreProcess.stderr.on("data", (d) => console.error(`[core] ${d}`));
  coreProcess.on("error", (err) => console.error("[core] failed to start:", err));
  coreProcess.on("exit", (code, signal) => {
    if (code !== 0 && code !== null) {
      console.error(`[core] exited unexpectedly: code=${code} signal=${signal}`);
    }
  });
}

// Polls /health so the window doesn't come up pointed at a core service
// that hasn't finished starting yet (SQLite open + migrations take a
// moment). Gives up after ~5s and loads the window anyway — the UI's own
// health check (Settings screen) surfaces a clear "unreachable" state
// rather than main.ts hanging indefinitely on a core that never starts.
function waitForCore(timeoutMs = 5000): Promise<void> {
  if (isDev) return Promise.resolve();

  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve) => {
    const attempt = () => {
      const req = http.get(`http://${CORE_ADDR}/health`, (res) => {
        res.resume();
        if (res.statusCode === 200) return resolve();
        retryOrGiveUp();
      });
      req.on("error", retryOrGiveUp);
      req.setTimeout(500, () => req.destroy());
    };
    const retryOrGiveUp = () => {
      if (Date.now() >= deadline) {
        console.warn("[core] did not become ready within timeout; loading UI anyway");
        return resolve();
      }
      setTimeout(attempt, 200);
    };
    attempt();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 640,
    title: "SentryBench",
    webPreferences: {
      // Electron security best practices: isolated, no remote content,
      // no direct filesystem access from the renderer.
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, "preload.js"),
    },
  });

  if (isDev) {
    mainWindow.loadURL("http://localhost:5173");
    mainWindow.webContents.openDevTools({ mode: "detach" });
  } else {
    mainWindow.loadFile(path.join(__dirname, "../dist/index.html"));
  }
}

// Auto-update: electron-updater reads the packaged app's own version (set
// from VERSION at build time via package.json's "version" field — see
// scripts/bump-version.sh and the release workflow, which keeps
// apps/desktop/package.json's version in sync with the repo-root VERSION)
// and compares it against the latest GitHub release. The Settings screen's
// version/changelog panel is a separate, always-live read of VERSION +
// CHANGELOG.md from the core service; this is "is a newer build available"
// rather than "what does this build contain".
function setupAutoUpdater() {
  if (isDev) return; // electron-updater no-ops without a packaged app anyway

  autoUpdater.autoDownload = false; // ask before using the user's bandwidth
  autoUpdater.on("update-available", (info) => {
    mainWindow?.webContents.send("sentrybench:update-available", info.version);
  });
  autoUpdater.on("update-downloaded", () => {
    mainWindow?.webContents.send("sentrybench:update-ready");
  });
  autoUpdater.on("error", (err) => {
    console.error("[auto-update]", err);
  });

  ipcMain.handle("sentrybench:check-for-updates", () => autoUpdater.checkForUpdates());
  ipcMain.handle("sentrybench:download-update", () => autoUpdater.downloadUpdate());
  ipcMain.handle("sentrybench:install-update", () => autoUpdater.quitAndInstall());

  autoUpdater.checkForUpdates().catch((err) => console.error("[auto-update] initial check failed", err));
}

// Creates (if needed) and loads a tab's BrowserView. tabId/proxyAddr come
// from the core service's browser-tab response; url is whatever the user
// typed or picked as the tab's starting page.
async function openBrowserTab(tabId: string, url: string, proxyAddr: string) {
  if (!mainWindow) return;
  if (browserViews.has(tabId)) {
    await browserViews.get(tabId)!.webContents.loadURL(url);
    return;
  }

  // Not "persist:<id>" on purpose — an in-memory partition that's gone the
  // moment this tab closes, so there's nothing left over to accidentally
  // reuse for a different identity later.
  const ses = electronSession.fromPartition(`sentrybench-browser-tab-${tabId}`, { cache: false });
  await ses.setProxy({ proxyRules: proxyAddr });

  // This tab's traffic is deliberately routed through SentryBench's own
  // local MITM proxy (core/internal/capture), so the TLS connection this
  // embedded page sees terminates at a leaf certificate our own
  // just-generated local CA signed a moment ago. Trusting that specific
  // CA's chain here is the point of the feature, not a bypass of it:
  // - scoped to ONLY this one throwaway, in-memory partition — never the
  //   app's own session, never any other tab, never the OS trust store
  // - the proxy's outbound leg to the real site is still verified
  //   normally (Go's default TLS transport, real root CAs) — only the
  //   proxy-to-this-tab leg, which is our own MITM by design, is trusted
  //   here instead of asking the user to also install the CA at the OS
  //   level just for this sandboxed browser
  ses.setCertificateVerifyProc((_request, callback) => callback(0));

  const view = new BrowserView({
    webPreferences: {
      session: ses,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.addBrowserView(view);
  browserViews.set(tabId, view);

  view.webContents.on("did-navigate", (_e, navUrl) => {
    mainWindow?.webContents.send("sentrybench:browser-url-changed", tabId, navUrl);
  });
  view.webContents.on("did-navigate-in-page", (_e, navUrl) => {
    mainWindow?.webContents.send("sentrybench:browser-url-changed", tabId, navUrl);
  });
  view.webContents.on("page-title-updated", (_e, title) => {
    mainWindow?.webContents.send("sentrybench:browser-title-changed", tabId, title);
  });

  await view.webContents.loadURL(url);
}

function setupBrowserTabIPC() {
  ipcMain.handle("sentrybench:browser-open-tab", (_e, tabId: string, url: string, proxyAddr: string) =>
    openBrowserTab(tabId, url, proxyAddr)
  );

  ipcMain.handle("sentrybench:browser-navigate", (_e, tabId: string, url: string) => {
    browserViews.get(tabId)?.webContents.loadURL(url);
  });

  ipcMain.handle(
    "sentrybench:browser-set-bounds",
    (_e, tabId: string, bounds: { x: number; y: number; width: number; height: number }) => {
      browserViews.get(tabId)?.setBounds(bounds);
    }
  );

  // tabId === null hides every tab's view (zero bounds) without
  // destroying them — used when the user navigates away from the Browser
  // page, so a BrowserView doesn't keep floating over Settings/Traffic/etc.
  // Passing a real tabId shows that one and hides the rest.
  ipcMain.handle("sentrybench:browser-switch-tab", (_e, tabId: string | null) => {
    if (!mainWindow) return;
    for (const [id, view] of browserViews) {
      if (id === tabId) {
        mainWindow.setTopBrowserView(view);
      } else {
        view.setBounds({ x: 0, y: 0, width: 0, height: 0 });
      }
    }
  });

  ipcMain.handle("sentrybench:browser-close-tab", (_e, tabId: string) => {
    const view = browserViews.get(tabId);
    if (view && mainWindow) {
      mainWindow.removeBrowserView(view);
      (view.webContents as unknown as { close?: () => void }).close?.();
    }
    browserViews.delete(tabId);
  });
}

app.whenReady().then(async () => {
  startCoreService();
  await waitForCore();
  createWindow();
  setupAutoUpdater();
  setupBrowserTabIPC();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  coreProcess?.kill();
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => {
  coreProcess?.kill();
});
