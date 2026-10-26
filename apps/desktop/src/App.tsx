import { useEffect } from "react";
import { Routes, Route, Navigate, Link, useLocation } from "react-router-dom";
import {
  ShieldCheck,
  LayoutDashboard,
  Radio,
  Globe,
  Send,
  Users,
  ShieldAlert,
  KeyRound,
  Binary,
  Settings as SettingsIcon,
  LogOut,
} from "lucide-react";
import { useAuthStore } from "./stores/authStore";
import WorkspaceSwitcher from "./components/WorkspaceSwitcher";
import Login from "./pages/Login";
import Workspaces from "./pages/Workspaces";
import Settings from "./pages/Settings";
import Traffic from "./pages/Traffic";
import Replay from "./pages/Replay";
import Identities from "./pages/Identities";
import JwtInspector from "./pages/JwtInspector";
import DecompressionInspector from "./pages/DecompressionInspector";
import Findings from "./pages/Findings";
import Browser from "./pages/Browser";

function RequireAuth({ children }: { children: JSX.Element }) {
  const token = useAuthStore((s) => s.token);
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

type NavEntry = { to: string; label: string; icon: React.ComponentType<{ size?: number }> };

const WORKSPACE_NAV: NavEntry[] = [
  { to: "/workspaces", label: "Overview", icon: LayoutDashboard },
  { to: "/traffic", label: "Traffic", icon: Radio },
  { to: "/browser", label: "Browser", icon: Globe },
  { to: "/replay", label: "Replay", icon: Send },
  { to: "/identities", label: "Identities", icon: Users },
  { to: "/findings", label: "Scans & Findings", icon: ShieldAlert },
];

const TOOLS_NAV: NavEntry[] = [
  { to: "/jwt", label: "JWT Inspector", icon: KeyRound },
  { to: "/decompression", label: "Decompression", icon: Binary },
];

const PAGE_TITLES: Record<string, string> = {
  "/workspaces": "Overview",
  "/traffic": "Traffic capture",
  "/browser": "Browser",
  "/replay": "Replay",
  "/identities": "Identity vault",
  "/findings": "Scans & findings",
  "/jwt": "JWT Inspector",
  "/decompression": "Decompression Inspector",
  "/settings": "Settings",
};

function NavSection({ title, items, pathname }: { title: string; items: NavEntry[]; pathname: string }) {
  return (
    <div className="mb-4">
      <div className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-600">
        {title}
      </div>
      <div className="flex flex-col gap-0.5">
        {items.map(({ to, label, icon: Icon }) => {
          const active = pathname === to;
          return (
            <Link
              key={to}
              to={to}
              className={`relative flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                active
                  ? "bg-indigo-500/15 text-indigo-300"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/70"
              }`}
            >
              {active && <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-full bg-indigo-400" />}
              <Icon size={16} />
              <span className="truncate">{label}</span>
            </Link>
          );
        })}
      </div>
    </div>
  );
}

function Shell({ children }: { children: React.ReactNode }) {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);
  const location = useLocation();
  const pageTitle = PAGE_TITLES[location.pathname] ?? "SentryBench";

  return (
    <div className="flex h-screen">
      <aside className="w-60 shrink-0 border-r border-slate-800 bg-slate-900/60 flex flex-col">
        <div className="px-4 py-4 border-b border-slate-800 flex items-center gap-2">
          <ShieldCheck size={20} className="text-indigo-400" />
          <div>
            <div className="text-sm font-semibold tracking-tight leading-none">SentryBench</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Authorized testing only</div>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto p-3 pt-4">
          <NavSection title="Workspace" items={WORKSPACE_NAV} pathname={location.pathname} />
          <NavSection title="Tools" items={TOOLS_NAV} pathname={location.pathname} />
        </nav>

        <div className="p-3 border-t border-slate-800">
          <Link
            to="/settings"
            className={`flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium mb-2 transition-colors ${
              location.pathname === "/settings"
                ? "bg-indigo-500/15 text-indigo-300"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/70"
            }`}
          >
            <SettingsIcon size={16} />
            Settings
          </Link>

          {user && (
            <div className="flex items-center gap-2 px-1 py-1.5">
              <span
                className="w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold text-slate-950 shrink-0"
                style={{ backgroundColor: user.avatarColor }}
              >
                {user.displayName.slice(0, 1).toUpperCase()}
              </span>
              <span className="text-xs text-slate-300 truncate flex-1">{user.displayName}</span>
              <button
                onClick={logout}
                title="Sign out"
                className="text-slate-500 hover:text-rose-400 transition-colors shrink-0"
              >
                <LogOut size={14} />
              </button>
            </div>
          )}
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-12 shrink-0 border-b border-slate-800 flex items-center justify-between px-5 bg-slate-950/60">
          <h1 className="text-sm font-medium text-slate-200">{pageTitle}</h1>
          <WorkspaceSwitcher />
        </header>
        <main className="flex-1 overflow-auto">{children}</main>
      </div>
    </div>
  );
}

export default function App() {
  const restoreSession = useAuthStore((s) => s.restoreSession);

  useEffect(() => {
    restoreSession();
  }, [restoreSession]);

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/workspaces"
        element={
          <RequireAuth>
            <Shell>
              <Workspaces />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/traffic"
        element={
          <RequireAuth>
            <Shell>
              <Traffic />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/browser"
        element={
          <RequireAuth>
            <Shell>
              <Browser />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/replay"
        element={
          <RequireAuth>
            <Shell>
              <Replay />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/identities"
        element={
          <RequireAuth>
            <Shell>
              <Identities />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/findings"
        element={
          <RequireAuth>
            <Shell>
              <Findings />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/jwt"
        element={
          <RequireAuth>
            <Shell>
              <JwtInspector />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/decompression"
        element={
          <RequireAuth>
            <Shell>
              <DecompressionInspector />
            </Shell>
          </RequireAuth>
        }
      />
      <Route
        path="/settings"
        element={
          <RequireAuth>
            <Shell>
              <Settings />
            </Shell>
          </RequireAuth>
        }
      />
      <Route path="*" element={<Navigate to="/workspaces" replace />} />
    </Routes>
  );
}
