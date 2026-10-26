import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { coreClient, Finding, Scan } from "../lib/coreClient";
import { useAuthStore } from "../stores/authStore";
import EmptyState from "../components/EmptyState";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

const SEVERITY_STYLE: Record<string, string> = {
  critical: "bg-red-900 text-red-100",
  high: "bg-red-700 text-red-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-blue-700 text-blue-100",
  info: "bg-slate-700 text-slate-200",
};

export default function Findings() {
  const token = useAuthStore((s) => s.token);
  const activeWorkspaceId = useAuthStore((s) => s.activeWorkspaceId);

  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [source, setSource] = useState<"traffic" | "requests" | "both">("traffic");
  const [scanning, setScanning] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  async function refresh(scanId?: string | null) {
    if (!token || !activeWorkspaceId) return;
    const [scanList, findingList] = await Promise.all([
      coreClient.listScans(token, activeWorkspaceId),
      coreClient.listFindings(token, activeWorkspaceId, scanId ?? undefined),
    ]);
    setScans(scanList);
    setFindings(findingList);
    setLoading(false);
  }

  useEffect(() => {
    refresh(selectedScanId);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeWorkspaceId]);

  async function handleRunScan() {
    if (!token || !activeWorkspaceId) return;
    setScanning(true);
    try {
      const scanRow = await coreClient.startScan(token, activeWorkspaceId, source);
      setSelectedScanId(scanRow.id);
      await pollScanUntilDone(scanRow.id);
    } finally {
      setScanning(false);
    }
  }

  // The scan runs in the background on the core service (see
  // runScan in router.go) — startScan returns immediately with
  // status "running". Poll the scan list until it flips to
  // completed/failed, then load its findings.
  async function pollScanUntilDone(scanId: string, attempt = 0) {
    if (!token || !activeWorkspaceId) return;
    const list = await coreClient.listScans(token, activeWorkspaceId);
    setScans(list);
    const current = list.find((s) => s.id === scanId);

    if (!current || current.status === "running") {
      if (attempt > 150) return; // ~5 minutes at 2s intervals — give up quietly
      await new Promise((r) => setTimeout(r, 2000));
      return pollScanUntilDone(scanId, attempt + 1);
    }

    const findingList = await coreClient.listFindings(token, activeWorkspaceId, scanId);
    setFindings(findingList);
  }

  async function handleSelectScan(id: string | null) {
    setSelectedScanId(id);
    await refresh(id);
  }

  async function handleDownload(format: "json" | "csv" | "html") {
    if (!token || !activeWorkspaceId) return;
    setDownloading(format);
    try {
      await coreClient.downloadReport(token, activeWorkspaceId, format);
    } finally {
      setDownloading(null);
    }
  }

  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  if (!activeWorkspaceId) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No workspace selected"
        description="Create or pick a workspace to run scans and review findings."
        actionLabel="Go to workspaces"
        actionTo="/workspaces"
      />
    );
  }

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert size={18} className="text-indigo-400" />
            <h1 className="text-lg font-semibold">Scans &amp; findings</h1>
          </div>
          <p className="text-sm text-slate-500">
            Passive checks over captured traffic and/or saved requests — missing headers, CORS, verbose
            errors, sensitive data in URLs, weak cookie flags, alg=none JWTs, version disclosure.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-2 mb-6">
        <select
          className="bg-slate-900 border border-slate-800 rounded-md px-2 py-2 text-sm"
          value={source}
          onChange={(e) => setSource(e.target.value as typeof source)}
        >
          <option value="traffic">Scan captured traffic</option>
          <option value="requests">Scan saved requests (sends them live)</option>
          <option value="both">Scan both</option>
        </select>
        <button
          onClick={handleRunScan}
          disabled={scanning}
          className="bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-md"
        >
          {scanning ? "Scanning..." : "Run scan"}
        </button>

        <div className="ml-auto flex gap-2">
          {(["json", "csv", "html"] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => handleDownload(fmt)}
              disabled={downloading === fmt}
              className="text-xs border border-slate-700 hover:border-slate-500 rounded-md px-2.5 py-1.5 text-slate-300"
            >
              {downloading === fmt ? "..." : `Export ${fmt.toUpperCase()}`}
            </button>
          ))}
        </div>
      </div>

      {scans.length > 0 && (
        <div className="flex items-center gap-2 mb-5 overflow-x-auto">
          <button
            onClick={() => handleSelectScan(null)}
            className={`text-xs px-2.5 py-1 rounded-md whitespace-nowrap ${
              selectedScanId === null ? "bg-indigo-500/20 text-indigo-300" : "text-slate-500 hover:text-slate-300"
            }`}
          >
            All scans
          </button>
          {scans.map((sc) => (
            <button
              key={sc.id}
              onClick={() => handleSelectScan(sc.id)}
              className={`text-xs px-2.5 py-1 rounded-md whitespace-nowrap ${
                selectedScanId === sc.id ? "bg-indigo-500/20 text-indigo-300" : "text-slate-500 hover:text-slate-300"
              }`}
            >
              {new Date(sc.startedAt).toLocaleString()} ·{" "}
              {sc.status === "running" ? "running..." : `${sc.findingsCount} findings`}
            </button>
          ))}
        </div>
      )}

      <div className="space-y-3">
        {loading && <div className="text-center py-10 text-sm text-slate-600">Loading...</div>}
        {sorted.map((f) => (
          <div key={f.id} className="border border-slate-800 rounded-lg p-4 bg-slate-900/40">
            <div className="flex items-center gap-2 mb-2">
              <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full ${SEVERITY_STYLE[f.severity]}`}>
                {f.severity}
              </span>
              <span className="text-sm font-medium">{f.title}</span>
            </div>
            <div className="text-xs text-slate-500 font-mono mb-2">
              {f.method} {f.url}
            </div>
            <div className="text-sm text-slate-400 mb-2">{f.description}</div>
            {f.evidence && (
              <pre className="text-xs font-mono whitespace-pre-wrap break-all bg-slate-950 border border-slate-800 rounded-md p-2 text-slate-400 mb-2">
                {f.evidence}
              </pre>
            )}
            {f.remediation && (
              <div className="text-xs text-emerald-400">
                <span className="font-medium">Remediation:</span> {f.remediation}
              </div>
            )}
          </div>
        ))}
        {!loading && sorted.length === 0 && (
          <div className="text-sm text-slate-600 text-center py-10">
            No findings yet. Capture some traffic or save a few requests, then run a scan.
          </div>
        )}
      </div>
    </div>
  );
}
