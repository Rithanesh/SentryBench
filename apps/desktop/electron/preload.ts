import { contextBridge, ipcRenderer } from "electron";

// The renderer never gets direct Node/filesystem access. It only talks to
// the Go core service over plain HTTP on localhost (see src/lib/coreClient.ts),
// which is already sandboxed to 127.0.0.1. This bridge exposes just enough
// to let the UI know it's running inside Electron (vs. a plain browser tab
// during `vite dev` preview) plus the app version for display.
contextBridge.exposeInMainWorld("sentrybench", {
  isElectron: true,
  platform: process.platform,

  // Auto-update bridge — thin and explicit on purpose: the renderer can
  // only ask to check/download/install, never reach arbitrary IPC.
  checkForUpdates: () => ipcRenderer.invoke("sentrybench:check-for-updates"),
  downloadUpdate: () => ipcRenderer.invoke("sentrybench:download-update"),
  installUpdate: () => ipcRenderer.invoke("sentrybench:install-update"),
  onUpdateAvailable: (callback: (version: string) => void) =>
    ipcRenderer.on("sentrybench:update-available", (_e, version) => callback(version)),
  onUpdateReady: (callback: () => void) =>
    ipcRenderer.on("sentrybench:update-ready", () => callback()),

  // Embedded Browser tabs — thin bridge, same shape as the IPC handlers
  // registered in electron/main.ts's setupBrowserTabIPC(). tabId is the ID
  // the core service assigned when it created that tab's proxy; the
  // renderer never talks to BrowserView directly, only through these.
  openBrowserTab: (tabId: string, url: string, proxyAddr: string) =>
    ipcRenderer.invoke("sentrybench:browser-open-tab", tabId, url, proxyAddr),
  navigateBrowserTab: (tabId: string, url: string) =>
    ipcRenderer.invoke("sentrybench:browser-navigate", tabId, url),
  setBrowserTabBounds: (tabId: string, bounds: { x: number; y: number; width: number; height: number }) =>
    ipcRenderer.invoke("sentrybench:browser-set-bounds", tabId, bounds),
  switchBrowserTab: (tabId: string | null) => ipcRenderer.invoke("sentrybench:browser-switch-tab", tabId),
  closeBrowserTab: (tabId: string) => ipcRenderer.invoke("sentrybench:browser-close-tab", tabId),
  onBrowserUrlChanged: (callback: (tabId: string, url: string) => void) =>
    ipcRenderer.on("sentrybench:browser-url-changed", (_e, tabId, url) => callback(tabId, url)),
  onBrowserTitleChanged: (callback: (tabId: string, title: string) => void) =>
    ipcRenderer.on("sentrybench:browser-title-changed", (_e, tabId, title) => callback(tabId, title)),
});

declare global {
  interface Window {
    sentrybench?: {
      isElectron: boolean;
      platform: string;
      checkForUpdates: () => Promise<unknown>;
      downloadUpdate: () => Promise<unknown>;
      installUpdate: () => Promise<unknown>;
      onUpdateAvailable: (callback: (version: string) => void) => void;
      onUpdateReady: (callback: () => void) => void;

      openBrowserTab: (tabId: string, url: string, proxyAddr: string) => Promise<void>;
      navigateBrowserTab: (tabId: string, url: string) => Promise<void>;
      setBrowserTabBounds: (
        tabId: string,
        bounds: { x: number; y: number; width: number; height: number }
      ) => Promise<void>;
      switchBrowserTab: (tabId: string | null) => Promise<void>;
      closeBrowserTab: (tabId: string) => Promise<void>;
      onBrowserUrlChanged: (callback: (tabId: string, url: string) => void) => void;
      onBrowserTitleChanged: (callback: (tabId: string, title: string) => void) => void;
    };
  }
}
