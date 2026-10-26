import { FormEvent, useEffect, useState } from "react";
import { Users } from "lucide-react";
import { coreClient, Identity } from "../lib/coreClient";
import { useAuthStore } from "../stores/authStore";
import EmptyState from "../components/EmptyState";

const AUTH_TYPES = ["bearer", "apiKey", "cookie", "basic", "custom", "none"] as const;

export default function Identities() {
  const token = useAuthStore((s) => s.token);
  const activeWorkspaceId = useAuthStore((s) => s.activeWorkspaceId);

  const [identities, setIdentities] = useState<Identity[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState("");
  const [role, setRole] = useState("");
  const [authType, setAuthType] = useState<string>("bearer");
  const [secret, setSecret] = useState(""); // token / apiKey / "user:pass" for basic

  async function refresh() {
    if (!token || !activeWorkspaceId) return;
    const list = await coreClient.listIdentities(token, activeWorkspaceId);
    setIdentities(list);
    setLoading(false);
  }

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeWorkspaceId]);

  async function handleCreate(e: FormEvent) {
    e.preventDefault();
    if (!token || !activeWorkspaceId || !name.trim()) return;
    await coreClient.createIdentity(token, activeWorkspaceId, {
      name: name.trim(),
      role: role.trim(),
      authType,
      token: secret,
    });
    setName("");
    setRole("");
    setSecret("");
    setShowNew(false);
    refresh();
  }

  async function handleDelete(id: string) {
    if (!token) return;
    await coreClient.deleteIdentity(token, id);
    refresh();
  }

  if (!activeWorkspaceId) {
    return (
      <EmptyState
        icon={Users}
        title="No workspace selected"
        description="Create or pick a workspace to start managing identities."
        actionLabel="Go to workspaces"
        actionTo="/workspaces"
      />
    );
  }

  return (
    <div className="p-6 max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-2">
            <Users size={18} className="text-indigo-400" />
            <h1 className="text-lg font-semibold">Identity vault</h1>
          </div>
          <p className="text-sm text-slate-500">
            Users, roles, and tokens to replay requests as, for authorization testing.
          </p>
        </div>
        <button
          onClick={() => setShowNew((v) => !v)}
          className="bg-indigo-500 hover:bg-indigo-400 text-white text-sm font-medium px-3 py-1.5 rounded-md"
        >
          New identity
        </button>
      </div>

      {showNew && (
        <form
          onSubmit={handleCreate}
          className="mb-6 border border-slate-800 rounded-lg p-4 bg-slate-900/60 space-y-3"
        >
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-slate-400 block mb-1">Name</label>
              <input
                className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="user_a, admin, anonymous..."
                required
              />
            </div>
            <div>
              <label className="text-xs text-slate-400 block mb-1">Role (optional)</label>
              <input
                className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500"
                value={role}
                onChange={(e) => setRole(e.target.value)}
                placeholder="standard user, admin, tenant-b..."
              />
            </div>
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Auth type</label>
            <select
              className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500"
              value={authType}
              onChange={(e) => setAuthType(e.target.value)}
            >
              {AUTH_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          {authType !== "none" && (
            <div>
              <label className="text-xs text-slate-400 block mb-1">
                {authType === "bearer" && "Bearer token"}
                {authType === "apiKey" && "API key"}
                {authType === "basic" && "username:password"}
                {authType === "cookie" && "Cookie value"}
                {authType === "custom" && "Credential value"}
              </label>
              <input
                className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm font-mono outline-none focus:border-indigo-500"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder={authType === "basic" ? "alice:hunter2" : "eyJhbGciOi..."}
              />
            </div>
          )}
          <div className="flex gap-2">
            <button
              type="submit"
              className="bg-indigo-500 hover:bg-indigo-400 text-white text-sm font-medium px-3 py-1.5 rounded-md"
            >
              Save identity
            </button>
            <button type="button" onClick={() => setShowNew(false)} className="text-sm text-slate-400 px-3 py-1.5">
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="space-y-2">
        {loading && <div className="text-center py-10 text-sm text-slate-600">Loading...</div>}
        {identities.map((id) => (
          <div
            key={id.id}
            className="border border-slate-800 rounded-lg p-3 bg-slate-900/40 flex items-center justify-between"
          >
            <div>
              <div className="text-sm font-medium">{id.name}</div>
              <div className="text-xs text-slate-500">
                {id.role || "no role"} · {id.authType}
              </div>
            </div>
            <button onClick={() => handleDelete(id.id)} className="text-xs text-slate-500 hover:text-rose-400">
              Delete
            </button>
          </div>
        ))}
        {!loading && identities.length === 0 && !showNew && (
          <div className="text-center py-10 text-sm text-slate-600">
            No identities yet — add one to start testing as different users or roles.
          </div>
        )}
      </div>
    </div>
  );
}
