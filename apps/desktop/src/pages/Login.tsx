import { FormEvent, useState } from "react";
import { Navigate } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuthStore } from "../stores/authStore";

export default function Login() {
  const token = useAuthStore((s) => s.token);
  const login = useAuthStore((s) => s.login);
  const register = useAuthStore((s) => s.register);
  const status = useAuthStore((s) => s.status);
  const error = useAuthStore((s) => s.error);

  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");

  if (token) return <Navigate to="/workspaces" replace />;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(email, password, displayName);
      }
    } catch {
      // error already captured in the store
    }
  }

  return (
    <div className="h-screen flex items-center justify-center bg-slate-950">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <div className="w-11 h-11 rounded-xl bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center mx-auto mb-3">
            <ShieldCheck size={22} className="text-indigo-400" />
          </div>
          <div className="text-xl font-semibold tracking-tight">SentryBench</div>
          <div className="text-sm text-slate-500 mt-1">
            Authorized API security testing workbench
          </div>
        </div>

        <div className="flex gap-1 mb-6 bg-slate-900 rounded-lg p-1">
          <button
            className={`flex-1 py-1.5 text-sm rounded-md transition-colors ${
              mode === "login" ? "bg-slate-800 text-slate-100" : "text-slate-500"
            }`}
            onClick={() => setMode("login")}
            type="button"
          >
            Sign in
          </button>
          <button
            className={`flex-1 py-1.5 text-sm rounded-md transition-colors ${
              mode === "register" ? "bg-slate-800 text-slate-100" : "text-slate-500"
            }`}
            onClick={() => setMode("register")}
            type="button"
          >
            Create account
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          {mode === "register" && (
            <div>
              <label className="text-xs text-slate-400 block mb-1">Display name</label>
              <input
                className="w-full bg-slate-900 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Jordan Avery"
                required
              />
            </div>
          )}
          <div>
            <label className="text-xs text-slate-400 block mb-1">Email</label>
            <input
              type="email"
              className="w-full bg-slate-900 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
            />
          </div>
          <div>
            <label className="text-xs text-slate-400 block mb-1">Password</label>
            <input
              type="password"
              className="w-full bg-slate-900 border border-slate-800 rounded-md px-3 py-2 text-sm outline-none focus:border-indigo-500"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 8 characters"
              minLength={8}
              required
            />
          </div>

          {error && <div className="text-xs text-rose-400">{error}</div>}

          <button
            type="submit"
            disabled={status === "loading"}
            className="w-full bg-indigo-500 hover:bg-indigo-400 disabled:opacity-50 text-white text-sm font-medium py-2 rounded-md transition-colors"
          >
            {status === "loading" ? "Please wait..." : mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>

        <p className="text-xs text-slate-600 text-center mt-6">
          Only use SentryBench against systems you own or are explicitly authorized to test.
        </p>
      </div>
    </div>
  );
}
