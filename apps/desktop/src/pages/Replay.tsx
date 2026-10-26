import { useEffect, useState } from "react";
import { Send } from "lucide-react";
import { coreClient, Identity, RequestResult, SavedRequest } from "../lib/coreClient";
import { useAuthStore } from "../stores/authStore";
import EmptyState from "../components/EmptyState";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export default function Replay() {
  const token = useAuthStore((s) => s.token);
  const activeWorkspaceId = useAuthStore((s) => s.activeWorkspaceId);

  const [requests, setRequests] = useState<SavedRequest[]>([]);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [listLoading, setListLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [draft, setDraft] = useState<{
    method: string;
    url: string;
    headersText: string;
    body: string;
    identityId: string | null;
  }>({ method: "GET", url: "", headersText: "", body: "", identityId: null });

  const [result, setResult] = useState<RequestResult | null>(null);
  const [sending, setSending] = useState(false);
  const [snippets, setSnippets] = useState<Record<string, string> | null>(null);
  const [snippetTab, setSnippetTab] = useState("curl");

  const [compareIds, setCompareIds] = useState<string[]>([]);
  const [compareResults, setCompareResults] = useState<Record<string, RequestResult> | null>(null);
  const [comparing, setComparing] = useState(false);
  const [showCompare, setShowCompare] = useState(false);

  async function refresh() {
    if (!token || !activeWorkspaceId) return;
    const [reqs, ids] = await Promise.all([
      coreClient.listRequests(token, activeWorkspaceId),
      coreClient.listIdentities(token, activeWorkspaceId),
    ]);
    setRequests(reqs);
    setIdentities(ids);
    setListLoading(false);
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeWorkspaceId]);

  function loadIntoEditor(req: SavedRequest | null) {
    setSelectedId(req?.id ?? null);
    setResult(null);
    setSnippets(null);
    setDraft({
      method: req?.method ?? "GET",
      url: req?.url ?? "",
      headersText: req ? Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join("\n") : "",
      body: req?.body ?? "",
      identityId: req?.identityId ?? null,
    });
  }

  function parseHeaders(text: string): Record<string, string> {
    const headers: Record<string, string> = {};
    for (const line of text.split("\n")) {
      const idx = line.indexOf(":");
      if (idx === -1) continue;
      const key = line.slice(0, idx).trim();
      const value = line.slice(idx + 1).trim();
      if (key) headers[key] = value;
    }
    return headers;
  }

  async function handleSaveAndSend() {
    if (!token || !activeWorkspaceId || !draft.url.trim()) return;
    setSending(true);
    setResult(null);
    try {
      let id = selectedId;
      const input = {
        method: draft.method,
        url: draft.url,
        headers: parseHeaders(draft.headersText),
        body: draft.body,
        identityId: draft.identityId,
      };
      if (id) {
        await coreClient.updateRequest(token, id, input);
      } else {
        const created = await coreClient.createRequest(token, activeWorkspaceId, input);
        id = created.id;
        setSelectedId(id);
      }
      await refresh();
      const res = await coreClient.sendRequest(token, id!);
      setResult(res);
    } finally {
      setSending(false);
    }
  }

  async function handleShowSnippets() {
    if (!token || !selectedId) return;
    const s = await coreClient.requestSnippets(token, selectedId);
    setSnippets(s);
  }

  function toggleCompareIdentity(id: string) {
    setCompareIds((ids) => (ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id]));
  }

  async function handleRunComparison() {
    if (!token || !selectedId || compareIds.length === 0) return;
    setComparing(true);
    setCompareResults(null);
    try {
      const results = await coreClient.sendRequestAsIdentities(token, selectedId, compareIds);
      setCompareResults(results);
    } finally {
      setComparing(false);
    }
  }

  // A quick authorization-testing signal: two identities that got the same
  // status AND near-identical body length likely received the same data —
  // worth a closer look if those identities are supposed to have different
  // access (the classic IDOR / broken-object-level-authorization pattern).
  // This flags it; it doesn't claim to have confirmed a vulnerability.
  function compareFlag(idA: string, idB: string): boolean {
    if (!compareResults) return false;
    const a = compareResults[idA];
    const b = compareResults[idB];
    if (!a || !b || a.error || b.error) return false;
    return a.status === b.status && Math.abs(a.sizeBytes - b.sizeBytes) < 20;
  }

  async function handleDelete(id: string) {
    if (!token) return;
    await coreClient.deleteRequest(token, id);
    if (id === selectedId) loadIntoEditor(null);
    refresh();
  }

  if (!activeWorkspaceId) {
    return (
      <EmptyState
        icon={Send}
        title="No workspace selected"
        description="Create or pick a workspace to start building and sending requests."
        actionLabel="Go to workspaces"
        actionTo="/workspaces"
      />
    );
  }

  return (
    <div className="flex h-full">
      <div className="w-64 border-r border-slate-800 overflow-y-auto">
        <div className="p-3 border-b border-slate-800 flex items-center justify-between">
          <span className="text-xs font-medium text-slate-400">Saved requests</span>
          <button onClick={() => loadIntoEditor(null)} className="text-xs text-indigo-400 hover:text-indigo-300">
            + New
          </button>
        </div>
        {listLoading && <div className="px-3 py-8 text-center text-xs text-slate-600">Loading...</div>}
        {!listLoading && requests.length === 0 && (
          <div className="px-3 py-8 text-center text-xs text-slate-600">
            No saved requests yet. Build one on the right, then Send to save it here.
          </div>
        )}
        {requests.map((r) => (
          <div
            key={r.id}
            onClick={() => loadIntoEditor(r)}
            className={`px-3 py-2 text-sm cursor-pointer flex items-center justify-between group ${
              r.id === selectedId ? "bg-indigo-500/10 text-indigo-300" : "hover:bg-slate-900 text-slate-300"
            }`}
          >
            <span className="truncate">
              <span className="text-[10px] font-mono text-slate-500 mr-1">{r.method}</span>
              {r.name}
            </span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                handleDelete(r.id);
              }}
              className="text-slate-600 hover:text-rose-400 opacity-0 group-hover:opacity-100 text-xs"
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="flex gap-2 mb-3">
          <select
            className="bg-slate-900 border border-slate-800 rounded-md px-2 py-2 text-sm font-mono"
            value={draft.method}
            onChange={(e) => setDraft((d) => ({ ...d, method: e.target.value }))}
          >
            {METHODS.map((m) => (
              <option key={m}>{m}</option>
            ))}
          </select>
          <input
            className="flex-1 bg-slate-900 border border-slate-800 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-indigo-500"
            placeholder="https://api.example.com/v1/orders/{{orderId}}"
            value={draft.url}
            onChange={(e) => setDraft((d) => ({ ...d, url: e.target.value }))}
          />
          <button
            onClick={handleSaveAndSend}
            disabled={sending || !draft.url.trim()}
            className="bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-sm font-medium px-4 py-2 rounded-md"
          >
            {sending ? "Sending..." : "Send"}
          </button>
        </div>

        <div className="flex gap-2 mb-4 items-center text-xs">
          <span className="text-slate-500">Identity:</span>
          <select
            className="bg-slate-900 border border-slate-800 rounded-md px-2 py-1 text-xs"
            value={draft.identityId ?? ""}
            onChange={(e) => setDraft((d) => ({ ...d, identityId: e.target.value || null }))}
          >
            <option value="">(none)</option>
            {identities.map((id) => (
              <option key={id.id} value={id.id}>
                {id.name}
              </option>
            ))}
          </select>
          {selectedId && (
            <>
              <button onClick={handleShowSnippets} className="text-indigo-400 hover:text-indigo-300 ml-2">
                Generate snippet
              </button>
              <button
                onClick={() => setShowCompare((v) => !v)}
                className="text-indigo-400 hover:text-indigo-300 ml-2"
              >
                Compare across identities
              </button>
            </>
          )}
        </div>

        {showCompare && selectedId && (
          <div className="mb-5 border border-slate-800 rounded-lg p-4 bg-slate-900/40">
            <div className="text-sm font-medium mb-2">Send as multiple identities</div>
            <p className="text-xs text-slate-500 mb-3">
              Sends this saved request once per selected identity and compares the responses — a quick way
              to spot an authorization issue (e.g. two identities that should see different data getting
              the same response).
            </p>
            <div className="flex flex-wrap gap-2 mb-3">
              {identities.map((id) => (
                <label
                  key={id.id}
                  className="flex items-center gap-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md px-2 py-1"
                >
                  <input
                    type="checkbox"
                    checked={compareIds.includes(id.id)}
                    onChange={() => toggleCompareIdentity(id.id)}
                  />
                  {id.name}
                </label>
              ))}
              {identities.length === 0 && (
                <span className="text-xs text-slate-600">No identities in this workspace yet.</span>
              )}
            </div>
            <button
              onClick={handleRunComparison}
              disabled={comparing || compareIds.length === 0}
              className="bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-xs font-medium px-3 py-1.5 rounded-md"
            >
              {comparing ? "Sending..." : `Send as ${compareIds.length || ""} identit${compareIds.length === 1 ? "y" : "ies"}`}
            </button>

            {compareResults && (
              <div className="mt-4 overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-slate-500 border-b border-slate-800">
                      <th className="py-1.5 pr-3">Identity</th>
                      <th className="py-1.5 pr-3">Status</th>
                      <th className="py-1.5 pr-3">Size</th>
                      <th className="py-1.5 pr-3">Time</th>
                      <th className="py-1.5">Flag</th>
                    </tr>
                  </thead>
                  <tbody>
                    {compareIds.map((id) => {
                      const r = compareResults[id];
                      const identityName = identities.find((i) => i.id === id)?.name ?? id;
                      const others = compareIds.filter((other) => other !== id);
                      const flagged = others.some((other) => compareFlag(id, other));
                      return (
                        <tr key={id} className="border-b border-slate-900">
                          <td className="py-1.5 pr-3 font-medium">{identityName}</td>
                          <td className="py-1.5 pr-3 font-mono">
                            {r?.error ? <span className="text-rose-400">error</span> : r?.status}
                          </td>
                          <td className="py-1.5 pr-3 text-slate-400">{r?.sizeBytes ?? "—"}B</td>
                          <td className="py-1.5 pr-3 text-slate-400">{r?.durationMs ?? "—"}ms</td>
                          <td className="py-1.5">
                            {flagged && (
                              <span className="text-amber-400" title="Same status + similar body size as another identity — worth a closer look">
                                ⚠ same-ish response
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-slate-400 block mb-1">Headers (one per line, Key: Value)</label>
            <textarea
              className="w-full h-32 bg-slate-900 border border-slate-800 rounded-md px-3 py-2 text-xs font-mono outline-none focus:border-indigo-500"
              value={draft.headersText}
              onChange={(e) => setDraft((d) => ({ ...d, headersText: e.target.value }))}
              placeholder={"Content-Type: application/json\nX-Custom-Header: value"}
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Body</label>
            <textarea
              className="w-full h-32 bg-slate-900 border border-slate-800 rounded-md px-3 py-2 text-xs font-mono outline-none focus:border-indigo-500"
              value={draft.body}
              onChange={(e) => setDraft((d) => ({ ...d, body: e.target.value }))}
              placeholder='{"key": "value"}'
            />
          </div>
        </div>

        {snippets && (
          <div className="mt-5 border border-slate-800 rounded-lg bg-slate-900/40">
            <div className="flex border-b border-slate-800 text-xs">
              {Object.keys(snippets).map((lang) => (
                <button
                  key={lang}
                  onClick={() => setSnippetTab(lang)}
                  className={`px-3 py-2 ${snippetTab === lang ? "text-indigo-300 border-b-2 border-indigo-500" : "text-slate-500"}`}
                >
                  {lang}
                </button>
              ))}
            </div>
            <pre className="p-3 text-xs font-mono whitespace-pre-wrap break-all text-slate-300">
              {snippets[snippetTab]}
            </pre>
          </div>
        )}

        {result && (
          <div className="mt-5 border border-slate-800 rounded-lg bg-slate-900/40 p-4">
            <div className="flex items-center gap-3 mb-3 text-sm">
              {result.error ? (
                <span className="text-rose-400 font-medium">Error: {result.error}</span>
              ) : (
                <>
                  <span
                    className={`font-mono font-semibold ${
                      result.status < 300 ? "text-emerald-400" : result.status < 400 ? "text-amber-400" : "text-rose-400"
                    }`}
                  >
                    {result.status}
                  </span>
                  <span className="text-slate-500">{result.durationMs}ms</span>
                  <span className="text-slate-500">{result.sizeBytes}B</span>
                </>
              )}
            </div>
            {!result.error && (
              <pre className="text-xs font-mono whitespace-pre-wrap break-all text-slate-300 max-h-80 overflow-y-auto">
                {result.body}
              </pre>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
