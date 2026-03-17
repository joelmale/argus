import axios from "axios";

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000",
  timeout: 15_000,
});

export const TOKEN_STORAGE_KEY = "argus_token";

// Attach JWT token from localStorage if present
api.interceptors.request.use((config) => {
  const token = typeof window !== "undefined" ? localStorage.getItem(TOKEN_STORAGE_KEY) : null;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export const authApi = {
  login: (username: string, password: string) =>
    api.post(
      "/api/v1/auth/token",
      new URLSearchParams({ username, password }),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
    ),
  me: () => api.get("/api/v1/auth/me"),
  listUsers: () => api.get("/api/v1/auth/users"),
  createUser: (payload: { username: string; password: string; email?: string; role: "admin" | "viewer" }) =>
    api.post("/api/v1/auth/users", payload),
  updateUser: (id: string, payload: { role?: "admin" | "viewer"; is_active?: boolean }) =>
    api.patch(`/api/v1/auth/users/${id}`, payload),
  listApiKeys: () => api.get("/api/v1/auth/api-keys"),
  createApiKey: (payload: { name: string }) => api.post("/api/v1/auth/api-keys", payload),
  deleteApiKey: (id: string) => api.delete(`/api/v1/auth/api-keys/${id}`),
  listAuditLogs: () => api.get("/api/v1/auth/audit-logs"),
  listAlertRules: () => api.get("/api/v1/auth/alert-rules"),
  updateAlertRule: (id: number, payload: { enabled?: boolean; notify_email?: boolean; notify_webhook?: boolean }) =>
    api.patch(`/api/v1/auth/alert-rules/${id}`, payload),
};

// ─── Asset endpoints ────────────────────────────────────────────
export const assetsApi = {
  list: (params?: { search?: string; status?: string; tag?: string }) =>
    api.get("/api/v1/assets/", { params }),
  exportCsv: () => api.get("/api/v1/assets/export.csv", { responseType: "blob" }),
  exportHtmlReport: () => api.get("/api/v1/assets/report.html", { responseType: "text" }),
  get: (id: string) => api.get(`/api/v1/assets/${id}`),
  update: (id: string, payload: Record<string, unknown>) => api.patch(`/api/v1/assets/${id}`, payload),
  addTag: (id: string, tag: string) => api.post(`/api/v1/assets/${id}/tags`, { tag }),
  removeTag: (id: string, tag: string) => api.delete(`/api/v1/assets/${id}/tags/${encodeURIComponent(tag)}`),
  delete: (id: string) => api.delete(`/api/v1/assets/${id}`),
};

// ─── Scan endpoints ─────────────────────────────────────────────
export const scansApi = {
  list: () => api.get("/api/v1/scans/"),
  trigger: (targets: string, scan_type = "balanced") =>
    api.post("/api/v1/scans/trigger", { targets, scan_type }),
  get: (id: string) => api.get(`/api/v1/scans/${id}`),
};

// ─── Topology endpoint ──────────────────────────────────────────
export const topologyApi = {
  getGraph: () => api.get("/api/v1/topology/graph"),
};

// ─── WebSocket helper ───────────────────────────────────────────
export function createWsConnection(onMessage: (e: MessageEvent) => void): WebSocket {
  const baseWsUrl = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000";
  const token = typeof window !== "undefined" ? localStorage.getItem(TOKEN_STORAGE_KEY) : null;
  const wsUrl = `${baseWsUrl}/ws/events${token ? `?token=${encodeURIComponent(token)}` : ""}`;
  const ws = new WebSocket(wsUrl);
  ws.onmessage = onMessage;
  return ws;
}
