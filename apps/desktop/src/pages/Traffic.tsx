import { useEffect, useRef, useState } from "react";
import { Radio } from "lucide-react";
import { coreClient, CapturedRequest } from "../lib/coreClient";
import { useAuthStore } from "../stores/authStore";
import EmptyState from "../components/EmptyState";

export default function Traffic() {
  const token = useAuthStore((s) => s.token);
  const activeWorkspaceId = useAuthStore((s) => s.activeWorkspaceId);

  const [running, setRunning] = useState(false);
  const [addr, setAddr] = useState("127.0.0.1:8080");
  const [interceptHttps, setInterceptHttps] = useState(true);
  const [traffic, setTraffic] = useState<CapturedRequest[]>([]);
  const [trafficLoading, setTrafficLoading] = useState(true);
  const [selected, setSelected] = useState<CapturedRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [downloadingCert, setDownloadingCert] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importMessage, setImportMessage] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  async function refreshStatus() {
    if (!token) return;
    const status = await coreClient.proxyStatus(token);
    setRunning(status.running);
    if (status.addr) setAddr(status.addr);
    if (status.interceptHttps !== undefined) setInterceptHttps(status.interceptHttps);
  }

  async function handleDownloadCert() {
    if (!token) return;
    setDownloadingCert(true);
    try {
      await coreClient.downloadCACert(token);
    } finally {
      setDownloadingCert(false);
    }
  }

  async function refreshTraffic() {
    if (!token || !activeWorkspaceId) return;
    const list = await coreClient.listTraffic(token, activeWorkspaceId);
    setTraffic(list);
    setTrafficLoading(false);
  }

  useEffect(() => {
    refreshStatus();
    refreshTraffic();
    const interval = setInterval(refreshTraffic, 3000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeWorkspaceId]);

  async function handleToggle() {
    if (!token || !activeWorkspaceId) return;
    setBusy(true);
    try {
      if (running) {
        await coreClient.proxyStop(token);
      } else {
        await coreClient.proxyStart(token, activeWorkspaceId, addr, undefined, interceptHttps);
      }
      await refreshStatus();
    } finally {
      setBusy(false);
    }
  }

  async function handleExport() {
    if (!token || !activeWorkspaceId) return;
    setExporting(true);
    try {
      await coreClient.exportHAR(token, activeWorkspaceId);
    } finally {
      setExporting(false);
    }
  }

  async function handleImportFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // allow re-selecting the same file later
    if (!file || !token || !activeWorkspaceId) return;
    setImporting(true);
    setImportMessage(null);
    try {
      const res = await coreClient.importHAR(token, activeWorkspaceId, file);
      setImportMessage(`Imported ${res.imported} requests.`);
      await refreshTraffic();
    } catch (err) {
      setImportMessage((err as Error).message);
    } finally {
      setImporting(false);
    }
  }

  if (!activeWorkspaceId) {
    return (
      <EmptyState
        icon={Radio}
        title="No workspace selected"
        description="Create or pick a workspace to start capturing traffic."
        actionLabel="Go to workspaces"
        actionTo="/workspaces"
      />
    );
  }

  return (
    <div className="flex h-full">
      <div className="flex-1 overflow-y-auto p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Radio size={18} className="text-indigo-400" />
              <h1 className="text-lg font-semibold">Traffic capture</h1>
            </div>
            <p className="text-sm text-slate-500">
              Route a browser or client through the local proxy to capture API calls.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleExport}
              disabled={exporting}
              className="text-xs border border-slate-700 hover:border-slate-500 rounded-md px-2.5 py-1.5 text-slate-300"
            >
              {exporting ? "..." : "Export HAR"}
            </button>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={importing}
              className="text-xs border border-slate-700 hover:border-slate-500 rounded-md px-2.5 py-1.5 text-slate-300"
            >
              {importing ? "Importing..." : "Import HAR"}
            </button>
            <input ref={fileInputRef} type="file" accept=".har,application/json" onChange={handleImportFile} className="hidden" />
          </div>
        </div>

        {importMessage && <div className="text-xs text-slate-400 mb-3">{importMessage}</div>}

        <div className="border border-slate-800 rounded-lg p-4 bg-slate-900/40 mb-3 flex items-center gap-3 flex-wrap">
          <input
            className="bg-slate-950 border border-slate-800 rounded-md px-3 py-1.5 text-sm font-mono w-48"
            value={addr}
            disabled={running}
            onChange={(e) => setAddr(e.target.value)}
          />
          <label className="flex items-center gap-1.5 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={interceptHttps}
              disabled={running}
              onChange={(e) => setInterceptHttps(e.target.checked)}
            />
            Intercept HTTPS (MITM)
          </label>
          <button
            onClick={handleToggle}
            disabled={busy}
            className={`text-sm font-medium px-4 py-1.5 rounded-md ${
              running ? "bg-rose-500/20 text-rose-300 hover:bg-rose-500/30" : "bg-indigo-500 hover:bg-indigo-400 text-white"
            }`}
          >
            {running ? "Stop proxy" : "Start proxy"}
          </button>
          <span className={`text-xs ${running ? "text-emerald-400" : "text-slate-500"}`}>
            {running ? "● capturing" : "○ stopped"}
          </span>
          <button
            onClick={handleDownloadCert}
            disabled={downloadingCert}
            className="ml-auto text-xs border border-slate-700 hover:border-slate-500 rounded-md px-2.5 py-1.5 text-slate-300"
          >
            {downloadingCert ? "..." : "Download CA certificate"}
          </button>
        </div>

        <div className="text-xs text-slate-500 mb-5 border border-slate-800 rounded-lg p-3 bg-slate-900/20 space-y-1">
          <div>
            Point your browser or API client's HTTP proxy at{" "}
            <code className="text-slate-300">{addr}</code>.
          </div>
          {interceptHttps ? (
            <>
              <div>
                HTTPS traffic is <span className="text-indigo-300">intercepted and captured in full</span> —
                but only once you've installed and trusted the CA certificate above in your OS or browser's
                trust store. Until then, HTTPS connections through this proxy will fail the TLS handshake
                (expected — that's the trust check working correctly), not silently go uncaptured.
              </div>
              <div>
                Only traffic through <em>this</em> proxy, from clients that trust that specific certificate,
                is affected. Remove it from your trust store at any time to undo this completely.
              </div>
            </>
          ) : (
            <div>
              HTTPS interception is off for this session — HTTPS traffic tunnels through uninspected
              (connections work normally, just aren't recorded). Check "Intercept HTTPS" before starting
              the proxy to capture it.
            </div>
          )}
        </div>

        <div className="space-y-1">
          {traffic.map((t) => (
            <div
              key={t.id}
              onClick={() => setSelected(t)}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm cursor-pointer ${
                selected?.id === t.id ? "bg-indigo-500/10" : "hover:bg-slate-900"
              }`}
            >
              <span className="text-[10px] font-mono text-slate-500 w-14">{t.method}</span>
              <span
                className={`text-xs font-mono w-10 ${
                  t.responseStatus < 300
                    ? "text-emerald-400"
                    : t.responseStatus < 400
                    ? "text-amber-400"
                    : "text-rose-400"
                }`}
              >
                {t.responseStatus || "—"}
              </span>
              <span className="truncate flex-1 text-slate-300">{t.path}</span>
              <span className="text-[11px] text-slate-600">{t.durationMs}ms</span>
            </div>
          ))}
          {trafficLoading && <div className="text-sm text-slate-600 px-3 py-6 text-center">Loading...</div>}
          {!trafficLoading && traffic.length === 0 && (
            <div className="text-sm text-slate-600 px-3 py-6 text-center">
              No traffic captured yet. Start the proxy and route a client through it.
            </div>
          )}
        </div>
      </div>

      {selected && (
        <div className="w-96 border-l border-slate-800 overflow-y-auto p-4 text-xs">
          <div className="font-mono text-slate-300 break-all mb-3">
            {selected.method} {selected.url}
          </div>
          <div className="text-slate-500 font-medium mb-1">Request headers</div>
          <pre className="whitespace-pre-wrap break-all text-slate-400 mb-3">
            {JSON.stringify(selected.requestHeaders, null, 2)}
          </pre>
          {selected.requestBody && (
            <>
              <div className="text-slate-500 font-medium mb-1">Request body</div>
              <pre className="whitespace-pre-wrap break-all text-slate-400 mb-3">{selected.requestBody}</pre>
            </>
          )}
          <div className="text-slate-500 font-medium mb-1">Response ({selected.responseStatus})</div>
          <pre className="whitespace-pre-wrap break-all text-slate-400">{selected.responseBody}</pre>
        </div>
      )}
    </div>
  );
}
