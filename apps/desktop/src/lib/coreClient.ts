// Thin fetch wrapper around the Go core service's localhost API.
// See core/internal/api/router.go for the matching endpoints.

const CORE_BASE_URL = "http://127.0.0.1:4317";

export type User = {
  id: string;
  email: string;
  displayName: string;
  avatarColor: string;
  createdAt: string;
};

export type Workspace = {
  id: string;
  ownerId: string;
  name: string;
  description: string;
  targetHosts: string[];
  createdAt: string;
  updatedAt: string;
};

export type VersionInfo = {
  version: string;
  title: string;
  changes: string[];
  builtWith: string;
};

export type AuthResponse = {
  token: string;
  user: User;
};

export type Identity = {
  id: string;
  workspaceId: string;
  name: string;
  role: string;
  authType: "bearer" | "apiKey" | "cookie" | "basic" | "custom" | "none";
  headers: Record<string, string>;
  cookies: Record<string, string>;
  createdAt: string;
};

export type SavedRequest = {
  id: string;
  workspaceId: string;
  name: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  body: string;
  identityId: string | null;
  createdAt: string;
  updatedAt: string;
};

export type RequestResult = {
  status: number;
  headers: Record<string, string>;
  body: string;
  durationMs: number;
  sizeBytes: number;
  identityId?: string;
  error?: string;
};

export type CapturedRequest = {
  id: string;
  workspaceId: string;
  method: string;
  url: string;
  host: string;
  path: string;
  requestHeaders: Record<string, string>;
  requestBody: string;
  responseStatus: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
  durationMs: number;
  capturedAt: string;
};

export type JwtDecoded = {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
  algorithm: string;
  isExpired: boolean;
  isNotYetValid: boolean;
  expiresAt?: string;
  notBefore?: string;
  issuedAt?: string;
  warnings: string[];
};

export type VerifyResult = { valid: boolean; error?: string };
export type WeakSecretResult = { cracked: boolean; secret?: string; attempted: number };
export type BrowserTab = {
  id: string;
  workspaceId: string;
  proxyAddr: string;
  label: string;
  createdAt: string;
};

export type TokenCandidate = {
  source: "header" | "cookie";
  name: string;
  value: string;
  suggestedAuthType: "bearer" | "cookie" | "apiKey";
  isJwt: boolean;
  seenAt: string;
  fromUrl: string;
};

export type Finding = {
  id: string;
  workspaceId: string;
  scanId: string;
  checkId: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  description: string;
  evidence: string;
  method: string;
  url: string;
  remediation: string;
  createdAt: string;
};

export type Scan = {
  id: string;
  workspaceId: string;
  status: "running" | "completed" | "failed";
  source: "traffic" | "requests" | "both";
  findingsCount: number;
  startedAt: string;
  completedAt?: string;
  error?: string;
};

export type DecompressionStep = {
  method: string;
  outputPreview: string;
  outputFull: string;
  inputSize: number;
  outputSize: number;
  error?: string;
};

async function request<T>(path: string, options: RequestInit = {}, token?: string): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${CORE_BASE_URL}${path}`, { ...options, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(body.error ?? `Request failed: ${res.status}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const coreClient = {
  health: () => request<{ status: string }>("/health"),
  version: () => request<VersionInfo>("/version"),

  register: (email: string, password: string, displayName: string) =>
    request<AuthResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password, displayName }),
    }),

  login: (email: string, password: string) =>
    request<AuthResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),

  me: (token: string) => request<User>("/me", {}, token),

  listWorkspaces: (token: string) => request<Workspace[]>("/workspaces", {}, token),

  createWorkspace: (token: string, input: { name: string; description?: string; targetHosts?: string[] }) =>
    request<Workspace>(
      "/workspaces",
      { method: "POST", body: JSON.stringify(input) },
      token
    ),

  deleteWorkspace: (token: string, id: string) =>
    request<void>(`/workspaces/${id}`, { method: "DELETE" }, token),

  // Identity vault
  listIdentities: (token: string, workspaceId: string) =>
    request<Identity[]>(`/workspaces/${workspaceId}/identities`, {}, token),

  createIdentity: (
    token: string,
    workspaceId: string,
    input: { name: string; role?: string; authType: string; token?: string; headers?: Record<string, string>; cookies?: Record<string, string> }
  ) =>
    request<Identity>(`/workspaces/${workspaceId}/identities`, { method: "POST", body: JSON.stringify(input) }, token),

  deleteIdentity: (token: string, id: string) =>
    request<void>(`/identities/${id}`, { method: "DELETE" }, token),

  // Replay workspace
  listRequests: (token: string, workspaceId: string) =>
    request<SavedRequest[]>(`/workspaces/${workspaceId}/requests`, {}, token),

  createRequest: (
    token: string,
    workspaceId: string,
    input: { name?: string; method: string; url: string; headers?: Record<string, string>; query?: Record<string, string>; body?: string; identityId?: string | null }
  ) =>
    request<SavedRequest>(`/workspaces/${workspaceId}/requests`, { method: "POST", body: JSON.stringify(input) }, token),

  updateRequest: (token: string, id: string, input: Partial<SavedRequest>) =>
    request<{ status: string }>(`/requests/${id}`, { method: "PATCH", body: JSON.stringify(input) }, token),

  deleteRequest: (token: string, id: string) =>
    request<void>(`/requests/${id}`, { method: "DELETE" }, token),

  sendRequest: (token: string, id: string) =>
    request<RequestResult>(`/requests/${id}/send`, { method: "POST" }, token),

  sendRequestAsIdentities: (token: string, id: string, identityIds: string[]) =>
    request<Record<string, RequestResult>>(
      `/requests/${id}/send-as-identities`,
      { method: "POST", body: JSON.stringify({ identityIds }) },
      token
    ),

  requestSnippets: (token: string, id: string) =>
    request<{ curl: string; powershell: string; python: string; javascript: string }>(
      `/requests/${id}/snippets`,
      {},
      token
    ),

  // Traffic capture
  proxyStart: (
    token: string,
    workspaceId: string,
    addr?: string,
    excludedDomains?: string[],
    interceptHttps = true
  ) =>
    request<{ status: string; addr: string }>(
      `/workspaces/${workspaceId}/proxy/start`,
      { method: "POST", body: JSON.stringify({ addr, excludedDomains, interceptHttps }) },
      token
    ),

  proxyStop: (token: string) => request<{ status: string }>("/proxy/stop", { method: "POST" }, token),

  proxyStatus: (token: string) =>
    request<{ running: boolean; paused: boolean; addr?: string; interceptHttps?: boolean }>(
      "/proxy/status",
      {},
      token
    ),

  // Downloads the local MITM root CA cert — the user must install + trust
  // this themselves (OS/browser trust store) before HTTPS interception
  // actually decrypts anything; see Traffic.tsx for the instructions shown.
  downloadCACert: async (token: string) => {
    const res = await fetch(`${CORE_BASE_URL}/proxy/ca-cert`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`CA cert download failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "sentrybench-ca.pem";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  listTraffic: (token: string, workspaceId: string) =>
    request<CapturedRequest[]>(`/workspaces/${workspaceId}/traffic`, {}, token),

  deleteTraffic: (token: string, id: string) =>
    request<void>(`/traffic/${id}`, { method: "DELETE" }, token),

  exportHAR: async (token: string, workspaceId: string) => {
    const res = await fetch(`${CORE_BASE_URL}/workspaces/${workspaceId}/traffic/export`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`HAR export failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "sentrybench-traffic.har";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },

  importHAR: async (token: string, workspaceId: string, harFile: File) => {
    const text = await harFile.text();
    const res = await fetch(`${CORE_BASE_URL}/workspaces/${workspaceId}/traffic/import`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: text,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(body.error ?? `HAR import failed: ${res.status}`);
    }
    return res.json() as Promise<{ imported: number }>;
  },

  // JWT inspector (stateless — no auth token needed, but harmless to send)
  jwtDecode: (jwtToken: string) =>
    request<JwtDecoded>("/jwt/decode", { method: "POST", body: JSON.stringify({ token: jwtToken }) }),

  jwtVerify: (jwtToken: string, algorithm: string, secretOrKey: { secret?: string; publicKeyPem?: string }) =>
    request<VerifyResult>("/jwt/verify", {
      method: "POST",
      body: JSON.stringify({ token: jwtToken, algorithm, ...secretOrKey }),
    }),

  jwtCheckWeakSecret: (jwtToken: string, candidates: string[]) =>
    request<WeakSecretResult>("/jwt/check-weak-secret", {
      method: "POST",
      body: JSON.stringify({ token: jwtToken, candidates }),
    }),

  // Decompression inspector
  decompressionDetect: (input: string) =>
    request<{ detected: string[] }>("/decompression/inspect", {
      method: "POST",
      body: JSON.stringify({ input }),
    }),

  decompressionApply: (method: string, input: string) =>
    request<DecompressionStep>("/decompression/inspect", {
      method: "POST",
      body: JSON.stringify({ method, input }),
    }),

  decompressionChain: (methods: string[], input: string) =>
    request<DecompressionStep[]>("/decompression/chain", {
      method: "POST",
      body: JSON.stringify({ methods, input }),
    }),

  // Embedded Browser tabs
  createBrowserTab: (token: string, workspaceId: string, label?: string) =>
    request<BrowserTab>(
      `/workspaces/${workspaceId}/browser-tabs`,
      { method: "POST", body: JSON.stringify({ label }) },
      token
    ),

  closeBrowserTab: (token: string, tabId: string) =>
    request<void>(`/browser-tabs/${tabId}`, { method: "DELETE" }, token),

  getSuggestedIdentity: (token: string, tabId: string) =>
    request<TokenCandidate[]>(`/browser-tabs/${tabId}/suggested-identity`, {}, token),

  // Scanning
  startScan: (token: string, workspaceId: string, source: "traffic" | "requests" | "both" = "traffic") =>
    request<Scan>(`/workspaces/${workspaceId}/scans`, { method: "POST", body: JSON.stringify({ source }) }, token),

  listScans: (token: string, workspaceId: string) =>
    request<Scan[]>(`/workspaces/${workspaceId}/scans`, {}, token),

  listFindings: (token: string, workspaceId: string, scanId?: string) =>
    request<Finding[]>(
      `/workspaces/${workspaceId}/findings${scanId ? `?scanId=${scanId}` : ""}`,
      {},
      token
    ),

  // Reporting — the endpoint is behind auth, so this fetches with the
  // bearer token and triggers a browser download from the resulting blob
  // rather than exposing a plain URL (which couldn't carry the header).
  downloadReport: async (token: string, workspaceId: string, format: "json" | "csv" | "html") => {
    const res = await fetch(`${CORE_BASE_URL}/workspaces/${workspaceId}/report?format=${format}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!res.ok) throw new Error(`Report download failed: ${res.status}`);
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sentrybench-report.${format}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
