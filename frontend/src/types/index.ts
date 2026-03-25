/** Core domain types — mirrors backend DB models */

export type AssetStatus = "online" | "offline" | "unknown";
export type DeviceType =
  | "router"
  | "switch"
  | "access_point"
  | "firewall"
  | "server"
  | "workstation"
  | "nas"
  | "printer"
  | "ip_camera"
  | "smart_tv"
  | "iot_device"
  | "voip"
  | "unknown";
export type UserRole = "admin" | "viewer";

export interface CurrentUser {
  id: string;
  username: string;
  email: string | null;
  role: UserRole;
  is_admin: boolean;
  is_active: boolean;
  created_at: string;
}

export interface ApiKey {
  id: string;
  name: string;
  key_prefix: string;
  is_active: boolean;
  last_used_at: string | null;
  created_at: string;
}

export interface AuditLogEntry {
  id: number;
  action: string;
  target_type: string | null;
  target_id: string | null;
  details: Record<string, unknown> | null;
  created_at: string;
  user: { id: string; username: string } | null;
}

export interface AlertRule {
  id: number;
  event_type: string;
  description: string | null;
  enabled: boolean;
  notify_email: boolean;
  notify_webhook: boolean;
  created_at: string;
}

export interface ConfigBackupTarget {
  id: number;
  asset_id: string;
  driver: string;
  username: string;
  password_env_var: string | null;
  port: number;
  host_override: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface ConfigBackupSnapshot {
  id: number;
  asset_id: string;
  target_id: number | null;
  status: "pending" | "running" | "done" | "failed";
  driver: string;
  command: string | null;
  content: string | null;
  error: string | null;
  captured_at: string;
}

export interface ConfigBackupPolicy {
  id: number;
  enabled: boolean;
  interval_minutes: number;
  tag_filter: string;
  retention_count: number;
  last_run_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScannerConfig {
  id: number;
  enabled: boolean;
  scheduled_scans_enabled: boolean;
  default_targets: string | null;
  auto_detect_targets: boolean;
  detected_targets: string | null;
  effective_targets: string | null;
  default_profile: string;
  interval_minutes: number;
  concurrent_hosts: number;
  host_chunk_size: number;
  top_ports_count: number;
  deep_probe_timeout_seconds: number;
  ai_after_scan_enabled: boolean;
  ai_backend: string;
  ai_model: string;
  fingerprint_ai_backend: string;
  ollama_base_url: string;
  openai_base_url: string;
  openai_api_key: string;
  anthropic_api_key: string;
  passive_arp_enabled: boolean;
  passive_arp_interface: string;
  snmp_enabled: boolean;
  snmp_version: string;
  snmp_community: string | null;
  snmp_timeout: number;
  snmp_v3_username: string | null;
  snmp_v3_auth_key: string | null;
  snmp_v3_priv_key: string | null;
  snmp_v3_auth_protocol: string;
  snmp_v3_priv_protocol: string;
  fingerprint_ai_enabled: boolean;
  fingerprint_ai_model: string;
  fingerprint_ai_min_confidence: number;
  fingerprint_ai_prompt_suffix: string | null;
  internet_lookup_enabled: boolean;
  internet_lookup_allowed_domains: string | null;
  internet_lookup_budget: number;
  internet_lookup_timeout_seconds: number;
  last_scheduled_scan_at: string | null;
  next_scheduled_scan_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface WirelessAssociation {
  id: number;
  access_point_asset_id: string;
  client_asset_id: string | null;
  client_mac: string | null;
  client_ip: string | null;
  ssid: string | null;
  band: string | null;
  signal_dbm: number | null;
  source: string;
  first_seen: string;
  last_seen: string;
}

export interface Finding {
  id: number;
  asset_id: string;
  port_id: number | null;
  source_tool: string;
  external_id: string | null;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  cve: string | null;
  service: string | null;
  port_number: number | null;
  protocol: string | null;
  metadata: Record<string, unknown> | null;
  first_seen: string;
  last_seen: string;
}

export interface BackupDriver {
  name: string;
  label: string;
  description: string;
}

export interface PluginInfo {
  name: string;
  version: string;
  description: string;
  capabilities: string[];
  health: string;
}

export interface IntegrationEvent {
  event: string;
  source: string;
  description: string;
  example: Record<string, unknown>;
}

export interface FingerprintDataset {
  id: number;
  key: string;
  name: string;
  category: string;
  description: string;
  upstream_url: string;
  local_path: string | null;
  update_mode: string;
  enabled: boolean;
  status: string;
  last_checked_at: string | null;
  last_updated_at: string | null;
  upstream_last_modified: string | null;
  etag: string | null;
  sha256: string | null;
  record_count: number | null;
  error: string | null;
  notes: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface TplinkDecoConfig {
  id: number;
  enabled: boolean;
  base_url: string;
  owner_username: string | null;
  effective_owner_username: string;
  owner_password: string | null;
  fetch_connected_clients: boolean;
  fetch_portal_logs: boolean;
  request_timeout_seconds: number;
  verify_tls: boolean;
  last_tested_at: string | null;
  last_sync_at: string | null;
  last_status: string;
  last_error: string | null;
  last_client_count: number | null;
  created_at: string;
  updated_at: string;
}

export interface TplinkDecoSyncRun {
  id: number;
  status: string;
  client_count: number | null;
  clients_payload: Array<Record<string, unknown>>;
  logs_excerpt: string | null;
  log_analysis: {
    health_score: number;
    event_count: number;
    issues: Array<{
      key: string;
      title: string;
      severity: string;
      issue: string;
      recommendation: string;
      count: number;
      health_penalty: number;
      sample_lines: string[];
      affected_macs: string[];
    }>;
    recommendations: Array<{
      title: string;
      severity: string;
      recommendation: string;
    }>;
    observed_macs: string[];
  } | null;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface HomeAssistantEntity {
  unique_id: string;
  name: string;
  state: string | number;
  entity_type: string;
  attributes?: Record<string, unknown>;
}

export interface HomeAssistantExport {
  entities: HomeAssistantEntity[];
  notes: string[];
}

export interface AssetAIAnalysis {
  device_class: DeviceType;
  confidence: number;
  vendor: string | null;
  model: string | null;
  os_guess: string | null;
  device_role: string | null;
  open_services_summary: string[];
  security_findings: Array<{ severity: string; title: string; detail: string }>;
  investigation_notes: string;
  suggested_tags: string[];
  ai_backend: string;
  model_used: string | null;
  agent_steps: number;
  analyzed_at: string;
}

export interface AssetEvidence {
  id: number;
  source: string;
  category: string;
  key: string;
  value: string;
  confidence: number;
  details: Record<string, unknown> | null;
  observed_at: string;
}

export interface ProbeRun {
  id: number;
  probe_type: string;
  target_port: number | null;
  success: boolean;
  duration_ms: number | null;
  summary: string | null;
  details: Record<string, unknown> | null;
  raw_excerpt: string | null;
  observed_at: string;
}

export interface PassiveObservation {
  id: number;
  source: string;
  event_type: string;
  summary: string;
  details: Record<string, unknown> | null;
  observed_at: string;
}

export interface FingerprintHypothesis {
  id: number;
  source: string;
  device_type: string | null;
  vendor: string | null;
  model: string | null;
  os_guess: string | null;
  confidence: number;
  summary: string;
  supporting_evidence: string[];
  prompt_version: string;
  model_used: string | null;
  raw_response: string | null;
  created_at: string;
}

export interface InternetLookupResult {
  id: number;
  query: string;
  domain: string;
  url: string;
  title: string;
  snippet: string | null;
  confidence: number;
  looked_up_at: string;
}

export interface LifecycleRecord {
  id: number;
  product: string;
  version: string | null;
  support_status: string;
  eol_date: string | null;
  reference: string | null;
  details: Record<string, unknown> | null;
  observed_at: string;
}

export interface AssetAutopsyStage {
  stage: string;
  status: string;
  summary: string;
  outputs: Record<string, unknown>;
}

export interface AssetAutopsy {
  id: number;
  trace: {
    asset_identity?: Record<string, unknown>;
    scan_context?: Record<string, unknown>;
    pipeline?: AssetAutopsyStage[];
    weak_points?: string[];
  };
  created_at: string;
  updated_at: string;
}

export interface Port {
  id: number;
  port_number: number;
  protocol: "tcp" | "udp";
  service: string | null;
  version: string | null;
  state: string;
}

export interface Asset {
  id: string;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  vendor: string | null;
  os_name: string | null;
  os_version: string | null;
  device_type: DeviceType | null;
  device_type_source: string;
  device_type_override: DeviceType | null;
  status: AssetStatus;
  notes: string | null;
  custom_fields: Record<string, unknown> | null;
  first_seen: string;
  last_seen: string;
  ports: Port[];
  tags: { tag: string }[];
  ai_analysis: AssetAIAnalysis | null;
  evidence: AssetEvidence[];
  probe_runs: ProbeRun[];
  observations: PassiveObservation[];
  fingerprint_hypotheses: FingerprintHypothesis[];
  internet_lookup_results: InternetLookupResult[];
  lifecycle_records: LifecycleRecord[];
  autopsy: AssetAutopsy | null;
}

export interface ScanJob {
  id: string;
  targets: string;
  scan_type: string;
  status: "pending" | "running" | "paused" | "cancelled" | "done" | "failed";
  triggered_by: string;
  queue_position?: number | null;
  started_at: string | null;
  finished_at: string | null;
  control_action?: string | null;
  control_mode?: string | null;
  resume_after?: string | null;
  result_summary: Record<string, unknown> | null;
  created_at: string;
}

export interface TopologyNode {
  data: {
    id: string;
    label: string;
    ip: string;
    vendor: string | null;
    os: string | null;
    status: AssetStatus;
    device_type: DeviceType | null;
  };
}

export interface TopologyEdge {
  data: {
    id: string;
    source: string;
    target: string;
    link_type: string;
    vlan_id: number | null;
  };
}

export interface TopologyGraph {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export type WsEvent =
  | { event: "device_discovered"; data: Asset }
  | { event: "device_updated"; data: { job_id: string; stage?: string; ip: string; hostname?: string | null } }
  | { event: "scan_progress"; data: { job_id: string; stage?: string; progress?: number; current_host?: string; hosts_found?: number; hosts_port_scanned?: number; hosts_fingerprinted?: number; hosts_deep_probed?: number; hosts_investigated?: number; assets_created?: number; assets_updated?: number; message?: string } }
  | { event: "scan_complete"; data: Record<string, unknown> }
  | { event: "device_investigated"; data: { job_id: string; ip: string; device_class: string; vendor: string | null; confidence: number } }
  | { event: "device_status_change"; data: { id: string; status: AssetStatus } }
  | { event: "heartbeat" };
