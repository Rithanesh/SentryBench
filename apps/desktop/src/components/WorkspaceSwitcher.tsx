import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, Check, Settings2 } from "lucide-react";
import { useAuthStore } from "../stores/authStore";

export default function WorkspaceSwitcher() {
  const workspaces = useAuthStore((s) => s.workspaces);
  const activeWorkspaceId = useAuthStore((s) => s.activeWorkspaceId);
  const setActiveWorkspace = useAuthStore((s) => s.setActiveWorkspace);

  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  const active = workspaces.find((w) => w.id === activeWorkspaceId);

  useEffect(() => {
    function onClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, []);

  if (workspaces.length === 0) {
    return (
      <Link
        to="/workspaces"
        className="text-xs text-slate-500 hover:text-slate-300 border border-slate-800 rounded-md px-2.5 py-1.5"
      >
        Create a workspace
      </Link>
    );
  }

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 border border-slate-800 hover:border-slate-700 bg-slate-900/60 rounded-md pl-3 pr-2 py-1.5 text-sm max-w-xs"
      >
        <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 shrink-0" />
        <span className="truncate text-slate-200">{active?.name ?? "Select workspace"}</span>
        <ChevronDown size={14} className="text-slate-500 shrink-0" />
      </button>

      {open && (
        <div className="absolute right-0 mt-1.5 w-72 bg-slate-900 border border-slate-800 rounded-lg shadow-xl z-50 py-1">
          <div className="px-3 py-1.5 text-[10px] font-medium uppercase tracking-wide text-slate-500">
            Workspaces
          </div>
          <div className="max-h-64 overflow-y-auto">
            {workspaces.map((ws) => (
              <button
                key={ws.id}
                onClick={() => {
                  setActiveWorkspace(ws.id);
                  setOpen(false);
                }}
                className="w-full flex items-center justify-between gap-2 px-3 py-2 text-sm text-left hover:bg-slate-800 transition-colors"
              >
                <span className="truncate text-slate-200">{ws.name}</span>
                {ws.id === activeWorkspaceId && <Check size={14} className="text-indigo-400 shrink-0" />}
              </button>
            ))}
          </div>
          <div className="border-t border-slate-800 mt-1 pt-1">
            <Link
              to="/workspaces"
              onClick={() => setOpen(false)}
              className="flex items-center gap-2 px-3 py-2 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <Settings2 size={13} />
              Manage workspaces
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
