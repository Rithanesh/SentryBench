import { create } from "zustand";
import { coreClient, User, Workspace } from "../lib/coreClient";

const TOKEN_STORAGE_KEY = "sentrybench.session.token";

type AuthState = {
  token: string | null;
  user: User | null;
  workspaces: Workspace[];
  activeWorkspaceId: string | null;
  status: "idle" | "loading" | "error";
  error: string | null;

  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, displayName: string) => Promise<void>;
  logout: () => void;
  restoreSession: () => Promise<void>;
  refreshWorkspaces: () => Promise<void>;
  createWorkspace: (name: string, description?: string) => Promise<void>;
  setActiveWorkspace: (id: string) => void;
};

export const useAuthStore = create<AuthState>((set, get) => ({
  token: null,
  user: null,
  workspaces: [],
  activeWorkspaceId: null,
  status: "idle",
  error: null,

  login: async (email, password) => {
    set({ status: "loading", error: null });
    try {
      const res = await coreClient.login(email, password);
      localStorage.setItem(TOKEN_STORAGE_KEY, res.token);
      set({ token: res.token, user: res.user, status: "idle" });
      await get().refreshWorkspaces();
    } catch (err) {
      set({ status: "error", error: (err as Error).message });
      throw err;
    }
  },

  register: async (email, password, displayName) => {
    set({ status: "loading", error: null });
    try {
      const res = await coreClient.register(email, password, displayName);
      localStorage.setItem(TOKEN_STORAGE_KEY, res.token);
      set({ token: res.token, user: res.user, status: "idle" });
      await get().refreshWorkspaces();
    } catch (err) {
      set({ status: "error", error: (err as Error).message });
      throw err;
    }
  },

  logout: () => {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
    set({ token: null, user: null, workspaces: [], activeWorkspaceId: null });
  },

  restoreSession: async () => {
    const token = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (!token) return;
    set({ status: "loading" });
    try {
      const user = await coreClient.me(token);
      set({ token, user, status: "idle" });
      await get().refreshWorkspaces();
    } catch {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
      set({ token: null, user: null, status: "idle" });
    }
  },

  refreshWorkspaces: async () => {
    const { token } = get();
    if (!token) return;
    const workspaces = await coreClient.listWorkspaces(token);
    set((state) => ({
      workspaces,
      activeWorkspaceId: state.activeWorkspaceId ?? workspaces[0]?.id ?? null,
    }));
  },

  createWorkspace: async (name, description = "") => {
    const { token } = get();
    if (!token) return;
    const ws = await coreClient.createWorkspace(token, { name, description });
    set((state) => ({
      workspaces: [...state.workspaces, ws],
      activeWorkspaceId: ws.id,
    }));
  },

  setActiveWorkspace: (id) => set({ activeWorkspaceId: id }),
}));
