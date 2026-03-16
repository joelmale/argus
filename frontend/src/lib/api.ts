import axios from "axios";

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000",
  timeout: 15_000,
});

// Attach JWT token from localStorage if present
api.interceptors.request.use((config) => {
  const token = typeof window !== "undefined" ? localStorage.getItem("argus_token") : null;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// ─── Asset endpoints ────────────────────────────────────────────
export const assetsApi = {
  list: (params?: { search?: string; status?: string; tag?: string }) =>
    api.get("/api/v1/assets/", { params }),
  get: (id: string) => api.get(`/api/v1/assets/${id}`),
  update: (id: string, payload: Record<string, unknown>) => api.patch(`/api/v1/assets/${id}`, payload),
  delete: (id: string) => api.delete(`/api/v1/assets/${id}`),
};

// ─── Scan endpoints ─────────────────────────────────────────────
export const scansApi = {
  list: () => api.get("/api/v1/scans/"),
  trigger: (targets: string, scan_type = "full") =>
    api.post("/api/v1/scans/trigger", null, { params: { targets, scan_type } }),
  get: (id: string) => api.get(`/api/v1/scans/${id}`),
};

// ─── Topology endpoint ──────────────────────────────────────────
export const topologyApi = {
  getGraph: () => api.get("/api/v1/topology/graph"),
};

// ─── WebSocket helper ───────────────────────────────────────────
export function createWsConnection(onMessage: (e: MessageEvent) => void): WebSocket {
  const wsUrl = (process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000") + "/ws/events";
  const ws = new WebSocket(wsUrl);
  ws.onmessage = onMessage;
  return ws;
}
