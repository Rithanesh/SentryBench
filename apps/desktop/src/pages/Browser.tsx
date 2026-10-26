import { useEffect, useRef, useState } from "react";
import { Globe, Plus, X, ArrowRight, KeyRound } from "lucide-react";
import { coreClient, TokenCandidate } from "../lib/coreClient";
import { useAuthStore } from "../stores/authStore";
import EmptyState from "../components/EmptyState";

type Tab = {
  id: string; // core service's browser-tab ID — also the BrowserView key
  label: string;
  url: string; // address bar value (updates as the page navigates)
  title: string;
};

const START_URL_DEFAULT = "https://";

export default function Browser() {
  const token = useAuthStore((s) => s.token);
  const activeWorkspaceId = useAuthStore((s) => s.activeWorkspaceId);

  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeTabId, setActiveTabId] = useState<string | null>(null);
  const [addressInput, setAddressInput] = useState("");
  const [opening, setOpening] = useState(false);

  const [candidates, setCandidates] = useState<TokenCandidate[] | null>(null);
  const [loadingCandidates, setLoadingCandidates] = useState(false);
  const [savingCandidate, setSavingCandidate] = useState<number | null>(null);
  const [identityNames, setIdentityNames] = useState<Record<number, string>>({});

  const viewportRef = useRef<HTMLDivElement>(null);
  const isElectron = typeof window !== "undefined" && !!window.sentrybench?.isElectron;

  // Keep the active BrowserView's screen bounds glued to this viewport div,
  // on every resize — the native view floats above the DOM, so it has no
  // idea where our React layout put its placeholder.
  useEffect(() => {
    if (!isElectron || !activeTabId) return;
    const el = viewportRef.current;
    if (!el) return;

    const updateBounds = () => {
      const rect = el.getBoundingClientRect();
      window.sentrybench?.setBrowserTabBounds(activeTabId, {
        x: Math.round(rect.left),
        y: Math.round(rect.top),
        width: Math.round(rect.width),
        height: Math.round(rect.height),
      });
    };

    updateBounds();
    const observer = new ResizeObserver(updateBounds);
    observer.observe(el);
    window.addEventListener("resize", updateBounds);
    return () => {
      observer.disconnect();
      window.removeEventListener("resize", updateBounds);
    };
  }, [activeTabId, isElectron]);

  // Show the active tab's view, hide the rest. Hide everything on unmount
  // so a BrowserView doesn't keep floating over other pages after
  // navigating away from /browser.
  useEffect(() => {
    if (!isElectron) return;
    window.sentrybench?.switchBrowserTab(activeTabId);
    return () => {
      window.sentrybench?.switchBrowserTab(null);
    };
  }, [activeTabId, isElectron]);

  // A BrowserView is a native layer Electron composites ON TOP of the
  // window's web contents — it ignores CSS z-index entirely, so the
  // candidate modal below (ordinary React/DOM) would render invisibly
  // underneath it otherwise. Hide the active view while the modal is open,
  // restore it when the modal closes.
  useEffect(() => {
    if (!isElectron) return;
    window.sentrybench?.switchBrowserTab(candidates ? null : activeTabId);
  }, [candidates, activeTabId, isElectron]);

  useEffect(() => {
    if (!isElectron) return;
    window.sentrybench?.onBrowserUrlChanged((tabId, url) => {
      setTabs((prev) => prev.map((t) => (t.id === tabId ? { ...t, url } : t)));
      setActiveTabId((current) => {
        if (current === tabId) setAddressInput(url);
        return current;
      });
    });
    window.sentrybench?.onBrowserTitleChanged((tabId, title) => {
      setTabs((prev) => prev.map((t) => (t.id === tabId ? { ...t, title } : t)));
    });
  }, [isElectron]);

  async function handleOpenTab() {
    if (!token || !activeWorkspaceId) return;
    setOpening(true);
    try {
      const url = addressForNewTab();
      const backendTab = await coreClient.createBrowserTab(token, activeWorkspaceId, url);
      await window.sentrybench?.openBrowserTab(backendTab.id, url, backendTab.proxyAddr);
      setTabs((prev) => [...prev, { id: backendTab.id, label: hostnameOf(url), url, title: hostnameOf(url) }]);
      setActiveTabId(backendTab.id);
      setAddressInput(url);
    } finally {
      setOpening(false);
    }
  }

  function addressForNewTab() {
    const typed = addressInput.trim();
    if (typed && typed !== START_URL_DEFAULT) return normalizeURL(typed);
    return "https://example.com";
  }

  async function handleNavigate() {
    if (!activeTabId) return;
    const url = normalizeURL(addressInput.trim());
    await window.sentrybench?.navigateBrowserTab(activeTabId, url);
  }

  async function handleCloseTab(tabId: string) {
    if (!token) return;
    await coreClient.closeBrowserTab(token, tabId);
    await window.sentrybench?.closeBrowserTab(tabId);
    setTabs((prev) => prev.filter((t) => t.id !== tabId));
    setActiveTabId((current) => {
      if (current !== tabId) return current;
      const remaining = tabs.filter((t) => t.id !== tabId);
      return remaining[remaining.length - 1]?.id ?? null;
    });
  }

  async function handleCaptureIdentity() {
    if (!token || !activeTabId) return;
    setLoadingCandidates(true);
    setCandidates(null);
    try {
      const result = await coreClient.getSuggestedIdentity(token, activeTabId);
      setCandidates(result);
      setIdentityNames({});
    } finally {
      setLoadingCandidates(false);
    }
  }

  async function handleSaveCandidate(index: number) {
    if (!token || !activeWorkspaceId || !candidates) return;
    const candidate = candidates[index];
    const name = identityNames[index]?.trim() || `${activeTab?.label ?? "Browser"} — ${candidate.name}`;
    setSavingCandidate(index);
    try {
      await coreClient.createIdentity(token, activeWorkspaceId, {
        name,
        authType: candidate.suggestedAuthType,
        token: candidate.suggestedAuthType === "bearer" ? stripBearerPrefix(candidate.value) : candidate.value,
        headers: candidate.source === "header" ? { [candidate.name]: candidate.value } : undefined,
        cookies: candidate.source === "cookie" ? { [candidate.name]: candidate.value } : undefined,
      });
      setCandidates((prev) => (prev ? prev.filter((_, i) => i !== index) : prev));
    } finally {
      setSavingCandidate(null);
    }
  }

  const activeTab = tabs.find((t) => t.id === activeTabId) ?? null;

  if (!activeWorkspaceId) {
    return (
      <EmptyState
        icon={Globe}
        title="No workspace selected"
        description="Create or pick a workspace to open the embedded browser."
        actionLabel="Go to workspaces"
        actionTo="/workspaces"
      />
    );
  }

  if (!isElectron) {
    return (
      <EmptyState
        icon={Globe}
        title="Embedded browser isn't available here"
        description="This feature needs the SentryBench desktop app (it drives a native, isolated browser view per tab) — not available in a plain web preview."
      />
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Tab bar */}
      <div className="flex items-center gap-1 border-b border-slate-800 bg-slate-900/60 px-2 pt-2 shrink-0">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => {
              setActiveTabId(tab.id);
              setAddressInput(tab.url);
            }}
            className={`group flex items-center gap-2 px-3 py-1.5 rounded-t-md text-xs max-w-[180px] transition-colors ${
              tab.id === activeTabId
                ? "bg-slate-950 text-slate-200"
                : "text-slate-500 hover:text-slate-300 hover:bg-slate-800/60"
            }`}
          >
            <span className="truncate">{tab.title || tab.label}</span>
            <X
              size={12}
              className="opacity-0 group-hover:opacity-100 hover:text-rose-400 shrink-0"
              onClick={(e) => {
                e.stopPropagation();
                handleCloseTab(tab.id);
              }}
            />
          </button>
        ))}
        <button
          onClick={handleOpenTab}
          disabled={opening}
          className="flex items-center gap-1 text-xs text-slate-500 hover:text-slate-200 px-2 py-1.5 rounded-t-md"
          title="New isolated tab"
        >
          <Plus size={14} />
        </button>
      </div>

      {/* Address bar */}
      {activeTab && (
        <div className="flex items-center gap-2 border-b border-slate-800 bg-slate-950 px-3 py-2 shrink-0">
          <input
            className="flex-1 bg-slate-900 border border-slate-800 rounded-md px-3 py-1.5 text-xs font-mono outline-none focus:border-indigo-500"
            value={addressInput}
            onChange={(e) => setAddressInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleNavigate()}
            placeholder="https://example.com/login"
          />
          <button
            onClick={handleNavigate}
            className="text-slate-400 hover:text-slate-200 border border-slate-800 rounded-md p-1.5"
          >
            <ArrowRight size={14} />
          </button>
          <button
            onClick={handleCaptureIdentity}
            disabled={loadingCandidates}
            className="flex items-center gap-1.5 bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-xs font-medium px-3 py-1.5 rounded-md whitespace-nowrap"
          >
            <KeyRound size={13} />
            {loadingCandidates ? "Scanning..." : "Capture identity"}
          </button>
        </div>
      )}

      {/* Viewport the native BrowserView is positioned over */}
      <div className="flex-1 relative bg-slate-950">
        {!activeTab && (
          <EmptyState
            icon={Globe}
            title="No tab open"
            description="Open an isolated tab, log in as a user, then capture their session as an Identity — log in as a different user in another tab to build up several."
          />
        )}
        <div ref={viewportRef} className="w-full h-full" />
      </div>

      {/* Candidate review modal — nothing is saved until the user confirms */}
      {candidates && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg w-full max-w-lg max-h-[80vh] overflow-y-auto">
            <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
              <div className="text-sm font-medium">Suggested credentials from this tab</div>
              <button onClick={() => setCandidates(null)} className="text-slate-500 hover:text-slate-200">
                <X size={16} />
              </button>
            </div>
            <div className="p-4 space-y-3">
              {candidates.length === 0 && (
                <div className="text-sm text-slate-500 text-center py-6">
                  Nothing detected yet — log in on this tab first, then try again.
                </div>
              )}
              {candidates.map((c, i) => (
                <div key={i} className="border border-slate-800 rounded-md p-3 bg-slate-950/60">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-mono text-slate-400">
                      {c.source === "header" ? "Header" : "Cookie"}: {c.name}
                      {c.isJwt && <span className="ml-1.5 text-indigo-400">(JWT)</span>}
                    </span>
                    <span className="text-[10px] text-slate-600">{c.suggestedAuthType}</span>
                  </div>
                  <div className="text-xs font-mono text-slate-500 break-all mb-2 max-h-16 overflow-y-auto">
                    {c.value}
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      className="flex-1 bg-slate-900 border border-slate-800 rounded-md px-2 py-1 text-xs outline-none focus:border-indigo-500"
                      placeholder={`${activeTab?.label ?? "Browser"} — ${c.name}`}
                      value={identityNames[i] ?? ""}
                      onChange={(e) => setIdentityNames((prev) => ({ ...prev, [i]: e.target.value }))}
                    />
                    <button
                      onClick={() => handleSaveCandidate(i)}
                      disabled={savingCandidate === i}
                      className="bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-xs font-medium px-3 py-1.5 rounded-md whitespace-nowrap"
                    >
                      {savingCandidate === i ? "Saving..." : "Save as identity"}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function normalizeURL(input: string): string {
  if (!/^https?:\/\//i.test(input)) return `https://${input}`;
  return input;
}

function hostnameOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function stripBearerPrefix(value: string): string {
  return value.replace(/^Bearer\s+/i, "");
}
