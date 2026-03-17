/** Core domain types — mirrors backend DB models */

export type AssetStatus = "online" | "offline" | "unknown";
export type DeviceType = "router" | "switch" | "server" | "workstation" | "iot" | "printer" | "unknown";
export type DeviceClass = DeviceType | "access_point" | "firewall" | "nas" | "ip_camera" | "smart_tv" | "iot_device" | "voip";
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
  status: AssetStatus;
  notes: string | null;
  custom_fields: Record<string, unknown> | null;
  first_seen: string;
  last_seen: string;
  ports: Port[];
  tags: { tag: string }[];
}

export interface ScanJob {
  id: string;
  targets: string;
  scan_type: string;
  status: "pending" | "running" | "done" | "failed";
  triggered_by: string;
  started_at: string | null;
  finished_at: string | null;
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
  | { event: "scan_progress"; data: { job_id: string; stage?: string; progress?: number; current_host?: string; hosts_found?: number; message?: string } }
  | { event: "scan_complete"; data: Record<string, unknown> }
  | { event: "device_investigated"; data: { job_id: string; ip: string; device_class: string; vendor: string | null; confidence: number } }
  | { event: "device_status_change"; data: { id: string; status: AssetStatus } }
  | { event: "heartbeat" };
