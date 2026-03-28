import axios from "axios";
import type { ConfigBackupPolicy, ConfigBackupTarget, FirewallaConfig, PfsenseConfig, ScannerConfig, TplinkDecoConfig, UnifiConfig } from "@/types";

function getApiBaseUrl() {
  return process.env.NEXT_PUBLIC_API_URL ?? "";
}

function getWsBaseUrl() {
  if (process.env.NEXT_PUBLIC_WS_URL) {
    return process.env.NEXT_PUBLIC_WS_URL;
  }
  if (typeof globalThis.window === "object") {
    return globalThis.location.origin.replace(/^http/i, "ws");
  }
  return "";
}

export const api = axios.create({
  baseURL: getApiBaseUrl(),
  timeout: 15_000,
});

export const TOKEN_STORAGE_KEY = "argus_token";

function hasBrowserWindow() {
  return typeof globalThis.window === "object";
}

function getBrowserStorageToken() {
  if (!hasBrowserWindow()) {
    return null;
  }
  return globalThis.localStorage.getItem(TOKEN_STORAGE_KEY);
}

// Attach JWT token from localStorage if present
api.interceptors.request.use((config) => {
  const token = getBrowserStorageToken();
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
  getSetupStatus: () => api.get("/api/v1/auth/setup/status"),
  initializeFirstAdmin: (payload: { username: string; password: string; email?: string }) =>
    api.post("/api/v1/auth/setup/initialize", payload),
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
  listBackupDrivers: () => api.get("/api/v1/system/backup-drivers"),
  listPlugins: () => api.get("/api/v1/system/plugins"),
  listIntegrationEvents: () => api.get("/api/v1/system/integration-events"),
  listFingerprintDatasets: () => api.get("/api/v1/system/fingerprint-datasets"),
  refreshFingerprintDataset: (key: string) => api.post(`/api/v1/system/fingerprint-datasets/${encodeURIComponent(key)}/refresh`),
  getHomeAssistantEntities: () => api.get("/api/v1/system/integrations/home-assistant/entities"),
  getInventorySyncExport: () => api.get("/api/v1/system/integrations/inventory-sync"),
  getBackupPolicy: () => api.get("/api/v1/system/backup-policy"),
  updateBackupPolicy: (payload: Omit<ConfigBackupPolicy, "id" | "last_run_at" | "created_at" | "updated_at">) =>
    api.put("/api/v1/system/backup-policy", payload),
  getScannerConfig: () => api.get("/api/v1/system/scanner-config"),
  updateScannerConfig: (payload: Omit<ScannerConfig, "id" | "detected_targets" | "effective_targets" | "last_scheduled_scan_at" | "next_scheduled_scan_at" | "created_at" | "updated_at">) =>
    api.put("/api/v1/system/scanner-config", payload),
  testAiConfiguration: () => api.post("/api/v1/system/ai/test", {}, { timeout: 60_000 }),
  listOllamaModels: (base_url?: string) => api.get("/api/v1/system/ai/ollama/models", { params: base_url ? { base_url } : undefined }),
  pullOllamaModel: (payload: { model: string; base_url?: string | null }) => api.post("/api/v1/system/ai/ollama/pull", payload),
  getTplinkDecoModule: () => api.get("/api/v1/system/modules/tplink-deco"),
  updateTplinkDecoModule: (payload: Omit<TplinkDecoConfig, "id" | "effective_owner_username" | "last_tested_at" | "last_sync_at" | "last_status" | "last_error" | "last_client_count" | "created_at" | "updated_at">) =>
    api.put("/api/v1/system/modules/tplink-deco", payload),
  testTplinkDecoModule: () => api.post("/api/v1/system/modules/tplink-deco/test"),
  syncTplinkDecoModule: () => api.post("/api/v1/system/modules/tplink-deco/sync"),
  getUnifiModule: () => api.get("/api/v1/system/modules/unifi"),
  updateUnifiModule: (payload: Omit<UnifiConfig, "id" | "last_tested_at" | "last_sync_at" | "last_status" | "last_error" | "last_client_count" | "last_device_count" | "created_at" | "updated_at">) =>
    api.put("/api/v1/system/modules/unifi", payload),
  testUnifiModule: () => api.post("/api/v1/system/modules/unifi/test"),
  syncUnifiModule: () => api.post("/api/v1/system/modules/unifi/sync"),
  getPfsenseModule: () => api.get("/api/v1/system/modules/pfsense"),
  updatePfsenseModule: (payload: Omit<PfsenseConfig, "id" | "last_tested_at" | "last_sync_at" | "last_status" | "last_error" | "last_lease_count" | "created_at" | "updated_at">) =>
    api.put("/api/v1/system/modules/pfsense", payload),
  testPfsenseModule: () => api.post("/api/v1/system/modules/pfsense/test"),
  syncPfsenseModule: () => api.post("/api/v1/system/modules/pfsense/sync"),
  getFirewallaModule: () => api.get("/api/v1/system/modules/firewalla"),
  updateFirewallaModule: (payload: Omit<FirewallaConfig, "id" | "last_tested_at" | "last_sync_at" | "last_status" | "last_error" | "last_device_count" | "created_at" | "updated_at">) =>
    api.put("/api/v1/system/modules/firewalla", payload),
  testFirewallaModule: () => api.post("/api/v1/system/modules/firewalla/test"),
  syncFirewallaModule: () => api.post("/api/v1/system/modules/firewalla/sync"),
  resetInventory: (payload: { confirm: string; include_scan_history: boolean }) =>
    api.post("/api/v1/system/inventory/reset", payload),
};

// ─── Asset endpoints ────────────────────────────────────────────
export const assetsApi = {
  list: (params?: { search?: string; status?: string; tag?: string }) =>
    api.get("/api/v1/assets/", { params }),
  exportCsv: () => api.get("/api/v1/assets/export.csv", { responseType: "blob" }),
  exportAnsible: () => api.get("/api/v1/assets/export.ansible.ini", { responseType: "blob" }),
  exportTerraform: () => api.get("/api/v1/assets/export.terraform.tf.json", { responseType: "blob" }),
  exportInventoryJson: () => api.get("/api/v1/assets/export.inventory.json", { responseType: "blob" }),
  exportJsonReport: () => api.get("/api/v1/assets/report.json", { responseType: "blob" }),
  exportHtmlReport: () => api.get("/api/v1/assets/report.html", { responseType: "text" }),
  get: (id: string) => api.get(`/api/v1/assets/${id}`),
  update: (id: string, payload: Record<string, unknown>) => api.patch(`/api/v1/assets/${id}`, payload),
  addTag: (id: string, tag: string) => api.post(`/api/v1/assets/${id}/tags`, { tag }),
  removeTag: (id: string, tag: string) => api.delete(`/api/v1/assets/${id}/tags/${encodeURIComponent(tag)}`),
  delete: (id: string) => api.delete(`/api/v1/assets/${id}`),
  bulkDelete: (asset_ids: string[]) => api.post('/api/v1/assets/bulk-delete', { asset_ids }),
  runPortScan: (id: string) => api.post(`/api/v1/assets/${id}/port-scan`),
  refreshSnmp: (id: string) => api.post(`/api/v1/assets/${id}/snmp-refresh`),
  refreshAiAnalysis: (id: string) => api.post(`/api/v1/assets/${id}/ai-analysis/refresh`),
  listNotes: (id: string) => api.get(`/api/v1/assets/${id}/notes`),
  addNote: (id: string, content: string) => api.post(`/api/v1/assets/${id}/notes`, { content }),
  getConfigBackupTarget: (id: string) => api.get(`/api/v1/assets/${id}/config-backup-target`),
  upsertConfigBackupTarget: (
    id: string,
    payload: Omit<ConfigBackupTarget, "id" | "asset_id" | "created_at" | "updated_at">,
  ) => api.put(`/api/v1/assets/${id}/config-backup-target`, payload),
  listConfigBackups: (id: string) => api.get(`/api/v1/assets/${id}/config-backups`),
  triggerConfigBackup: (id: string) => api.post(`/api/v1/assets/${id}/config-backups`),
  downloadConfigBackup: (id: string, snapshotId: number) => api.get(`/api/v1/assets/${id}/config-backups/${snapshotId}/download`, { responseType: "blob" }),
  diffConfigBackup: (id: string, snapshotId: number, compareTo?: number) => {
    const params = compareTo === undefined ? undefined : { compare_to: compareTo };
    return api.get(`/api/v1/assets/${id}/config-backups/${snapshotId}/diff`, { params, responseType: "text" });
  },
  getRestoreAssist: (id: string, snapshotId: number) => api.get(`/api/v1/assets/${id}/config-backups/${snapshotId}/restore-assist`),
  listWirelessClients: (id: string) => api.get(`/api/v1/assets/${id}/wireless-clients`),
  listFindings: (id: string) => api.get(`/api/v1/assets/${id}/findings`),
};

// ─── Scan endpoints ─────────────────────────────────────────────
export const scansApi = {
  list: () => api.get("/api/v1/scans/"),
  trigger: (targets?: string, scan_type = "balanced") =>
    api.post("/api/v1/scans/trigger", { targets: targets?.trim() || undefined, scan_type }),
  get: (id: string) => api.get(`/api/v1/scans/${id}`),
  control: (id: string, payload: { action: "cancel" | "pause" | "resume"; mode?: "discard" | "preserve_discovery"; resume_in_minutes?: number }) =>
    api.post(`/api/v1/scans/${id}/control`, payload),
  queue: (id: string, payload: { action: "move_up" | "move_down" | "move_to_front" | "start_now" }) =>
    api.post(`/api/v1/scans/${id}/queue`, payload),
  clearQueue: () => api.post("/api/v1/scans/queue/clear"),
};

export const findingsApi = {
  list: (params?: { severity?: string; status?: string; asset_id?: string }) =>
    api.get("/api/v1/findings/", { params }),
  summary: () => api.get("/api/v1/findings/summary"),
  ingest: (payload: { source_tool: string; findings: Array<Record<string, unknown>> }) =>
    api.post("/api/v1/findings/ingest", payload),
  update: (id: number, payload: { status: string }) => api.patch(`/api/v1/findings/${id}`, payload),
};

// ─── Topology endpoint ──────────────────────────────────────────
export const topologyApi = {
  getGraph: () => api.get("/api/v1/topology/graph"),
};

// ─── WebSocket helper ───────────────────────────────────────────
export function createWsConnection(onMessage: (e: MessageEvent) => void): WebSocket {
  const baseWsUrl = getWsBaseUrl();
  const token = getBrowserStorageToken();
  const tokenQuery = token ? `?token=${encodeURIComponent(token)}` : "";
  const wsUrl = `${baseWsUrl}/ws/events${tokenQuery}`;
  const ws = new WebSocket(wsUrl);
  ws.onmessage = onMessage;
  return ws;
}
