import { useEffect, useState } from "react";
import { Settings as SettingsIcon } from "lucide-react";
import { coreClient, VersionInfo } from "../lib/coreClient";
import { useAuthStore } from "../stores/authStore";

export default function Settings() {
  const user = useAuthStore((s) => s.user);
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [health, setHealth] = useState<"checking" | "ok" | "down">("checking");
  const [updateState, setUpdateState] = useState<"idle" | "available" | "downloading" | "ready">("idle");
  const [availableVersion, setAvailableVersion] = useState<string | null>(null);

  useEffect(() => {
    coreClient
      .version()
      .then(setVersion)
      .catch(() => setVersion(null));
    coreClient
      .health()
      .then(() => setHealth("ok"))
      .catch(() => setHealth("down"));

    window.sentrybench?.onUpdateAvailable((v) => {
      setAvailableVersion(v);
      setUpdateState("available");
    });
    window.sentrybench?.onUpdateReady(() => setUpdateState("ready"));
  }, []);

  async function handleDownloadUpdate() {
    setUpdateState("downloading");
    await window.sentrybench?.downloadUpdate();
  }

  async function handleInstallUpdate() {
    await window.sentrybench?.installUpdate();
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-8">
      <div>
        <div className="flex items-center gap-2">
          <SettingsIcon size={18} className="text-indigo-400" />
          <h1 className="text-lg font-semibold">Settings</h1>
        </div>
        <p className="text-sm text-slate-500">Account, core service status, and version info.</p>
      </div>

      <section>
        <h2 className="text-sm font-medium text-slate-300 mb-3">Profile</h2>
        {user && (
          <div className="flex items-center gap-3 border border-slate-800 rounded-lg p-4 bg-slate-900/40">
            <span
              className="w-10 h-10 rounded-full flex items-center justify-center font-bold text-slate-950"
              style={{ backgroundColor: user.avatarColor }}
            >
              {user.displayName.slice(0, 1).toUpperCase()}
            </span>
            <div>
              <div className="font-medium text-sm">{user.displayName}</div>
              <div className="text-xs text-slate-500">{user.email}</div>
            </div>
          </div>
        )}
      </section>

      <section>
        <h2 className="text-sm font-medium text-slate-300 mb-3">Core service</h2>
        <div className="border border-slate-800 rounded-lg p-4 bg-slate-900/40 flex items-center justify-between">
          <span className="text-sm text-slate-400">Status</span>
          <span
            className={`text-xs font-medium px-2 py-0.5 rounded-full ${
              health === "ok"
                ? "bg-emerald-500/15 text-emerald-400"
                : health === "down"
                ? "bg-rose-500/15 text-rose-400"
                : "bg-slate-700/40 text-slate-400"
            }`}
          >
            {health === "ok" ? "Connected" : health === "down" ? "Unreachable" : "Checking..."}
          </span>
        </div>
      </section>

      <section>
        <h2 className="text-sm font-medium text-slate-300 mb-3">Version</h2>
        <div className="border border-slate-800 rounded-lg p-4 bg-slate-900/40">
          {version ? (
            <>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-semibold">v{version.version}</span>
                <span className="text-xs text-slate-500">{version.title}</span>
              </div>
              {version.changes.length > 0 && (
                <ul className="mt-3 space-y-1">
                  {version.changes.map((change, i) => (
                    <li key={i} className="text-sm text-slate-400 flex gap-2">
                      <span className="text-indigo-400">•</span>
                      <span>{change}</span>
                    </li>
                  ))}
                </ul>
              )}
              <p className="text-[11px] text-slate-600 mt-4">
                Pulled live from VERSION and CHANGELOG.md via the core service's
                GET /version endpoint — every update to this app updates this panel
                automatically, no separate UI edit needed.
              </p>

              {updateState !== "idle" && (
                <div className="mt-4 border-t border-slate-800 pt-4">
                  {updateState === "available" && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-indigo-300">
                        Update available: v{availableVersion}
                      </span>
                      <button
                        onClick={handleDownloadUpdate}
                        className="text-xs bg-indigo-500 hover:bg-indigo-400 text-white font-medium px-3 py-1.5 rounded-md"
                      >
                        Download
                      </button>
                    </div>
                  )}
                  {updateState === "downloading" && (
                    <span className="text-sm text-slate-400">Downloading update...</span>
                  )}
                  {updateState === "ready" && (
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-emerald-400">Update ready to install.</span>
                      <button
                        onClick={handleInstallUpdate}
                        className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-3 py-1.5 rounded-md"
                      >
                        Restart &amp; install
                      </button>
                    </div>
                  )}
                </div>
              )}
            </>
          ) : (
            <div className="text-sm text-slate-500">
              Could not reach the core service to read version info.
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
