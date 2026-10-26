import { FormEvent, useState } from "react";
import { Link } from "react-router-dom";
import { FolderKanban, Plus, Radio, Globe, Send, Users, ShieldAlert, Check } from "lucide-react";
import { useAuthStore } from "../stores/authStore";
import EmptyState from "../components/EmptyState";

const QUICK_LINKS = [
  { label: "Traffic", desc: "Proxy capture + HTTPS interception", to: "/traffic", icon: Radio },
  { label: "Browser", desc: "Log in as multiple users, capture their tokens", to: "/browser", icon: Globe },
  { label: "Replay", desc: "Postman-style request editor", to: "/replay", icon: Send },
  { label: "Identities", desc: "Multi-identity auth testing", to: "/identities", icon: Users },
  { label: "Scans & Findings", desc: "Run checks, review results", to: "/findings", icon: ShieldAlert },
];

export default function Workspaces() {
  const workspaces = useAuthStore((s) => s.workspaces);
  const activeWorkspaceId = useAuthStore((s) => s.activeWorkspaceId);
  const setActiveWorkspace = useAuthStore((s) => s.setActiveWorkspace);
  const createWorkspace = useAuthStore((s) => s.createWorkspace);

  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    await createWorkspace(name.trim(), description.trim());
    setName("");
    setDescription("");
    setShowNew(false);
  }

  const active = workspaces.find((w) => w.id === activeWorkspaceId);

  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold">Workspaces</h1>
          <p className="text-sm text-slate-500">
            Like Postman, each workspace holds its own collections, identities, and findings.
          </p>
        </div>
        <button
          onClick={() => setShowNew((v) => !v)}
          className="flex items-center gap-1.5 bg-indigo-500 hover:bg-indigo-400 text-white text-sm font-medium px-3 py-1.5 rounded-md transition-colors"
        >
          <Plus size={15} />
          New workspace
        </button>
      </div>

      {showNew && (
        <form
          onSubmit={handleCreate}
          className="mb-6 border border-slate-800 rounded-lg p-4 bg-slate-900/60 space-y-3"
        >
          <div>
            <label className="text-xs text-slate-400 block mb-1">Name</label>
            <input
              autoFocus
              className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Acme Payments API — Q4 assessment"
              required
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Description (optional)</label>
            <input
              className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Authorized pentest for staging.acme.example"
            />
          </div>
          <div className="flex gap-2">
            <button
              type="submit"
              className="bg-indigo-500 hover:bg-indigo-400 text-white text-sm font-medium px-3 py-1.5 rounded-md transition-colors"
            >
              Create
            </button>
            <button
              type="button"
              onClick={() => setShowNew(false)}
              className="text-sm text-slate-400 hover:text-slate-200 px-3 py-1.5 transition-colors"
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      {workspaces.length === 0 && !showNew ? (
        <EmptyState
          icon={FolderKanban}
          title="No workspaces yet"
          description="Create your first workspace to start capturing traffic, saving requests, and running scans."
        />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {workspaces.map((ws) => {
            const isActive = ws.id === activeWorkspaceId;
            return (
              <button
                key={ws.id}
                onClick={() => setActiveWorkspace(ws.id)}
                className={`relative text-left border rounded-lg p-4 transition-colors ${
                  isActive
                    ? "border-indigo-500 bg-indigo-500/10"
                    : "border-slate-800 bg-slate-900/40 hover:border-slate-700"
                }`}
              >
                {isActive && (
                  <span className="absolute top-3 right-3 text-indigo-400">
                    <Check size={14} />
                  </span>
                )}
                <div className="font-medium text-sm pr-6">{ws.name}</div>
                {ws.description && <div className="text-xs text-slate-500 mt-1">{ws.description}</div>}
                <div className="text-[11px] text-slate-600 mt-3">
                  Created {new Date(ws.createdAt).toLocaleDateString()}
                </div>
              </button>
            );
          })}
        </div>
      )}

      {active && (
        <div className="mt-8 border-t border-slate-800 pt-6">
          <div className="text-sm text-slate-400 mb-3">
            Jump into <span className="text-slate-100 font-medium">{active.name}</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-sm">
            {QUICK_LINKS.map(({ label, desc, to, icon: Icon }) => (
              <Link
                key={label}
                to={to}
                className="border border-slate-800 rounded-lg p-3 bg-slate-900/40 hover:border-indigo-500/50 hover:bg-slate-900/70 transition-colors block"
              >
                <Icon size={16} className="text-indigo-400 mb-2" />
                <div className="font-medium">{label}</div>
                <div className="text-xs text-slate-500 mt-1">{desc}</div>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
