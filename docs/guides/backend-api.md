---
id: backend-api-guide
title: Backend API Guide
sidebar_position: 11
---

# Backend API Guide

`argus-backend` is the central API, orchestration, and persistence layer for Argus.

## Responsibilities

- REST API
- WebSocket event delivery
- auth and authorization
- persistence and change tracking
- findings ingestion
- scanner configuration management
- enrichment and integration endpoints

## Base URL

Development default:

```text
http://localhost:8000/api/v1
```

Interactive API docs:

```text
http://localhost:8000/docs
```

## Authentication

Supported methods:

- JWT bearer token
- `X-API-Key`

Role model:

- `admin`
- `viewer`

Typical behavior:

- `viewer` can read
- `admin` can mutate settings, trigger scans, manage users, and manage keys

## Main Route Groups

| Route Group | Purpose |
|---|---|
| `/auth` | login, user identity, user management, API keys |
| `/assets` | asset inventory, detail, exports, reports, asset actions |
| `/scans` | scan history, trigger, log ingestion |
| `/topology` | topology graph and manual links |
| `/findings` | finding list, summary, ingestion, status updates |
| `/system` | scanner settings, backup policy, plugin and integration settings |
| `/ws/events` | real-time event stream |

## Representative Endpoints

### Auth

```http
POST /api/v1/auth/token
GET  /api/v1/auth/me
GET  /api/v1/auth/users
POST /api/v1/auth/users
GET  /api/v1/auth/api-keys
POST /api/v1/auth/api-keys
```

### Assets

```http
GET    /api/v1/assets/
GET    /api/v1/assets/{id}
PATCH  /api/v1/assets/{id}
GET    /api/v1/assets/export.csv
GET    /api/v1/assets/export.inventory.json
GET    /api/v1/assets/export.ansible.ini
GET    /api/v1/assets/export.terraform.tf.json
GET    /api/v1/assets/report.json
GET    /api/v1/assets/report.html
```

### Scans

```http
GET  /api/v1/scans/
POST /api/v1/scans/trigger
POST /api/v1/scans/ingest/logs
GET  /api/v1/scans/{job_id}
```

### Findings

```http
GET   /api/v1/findings/
GET   /api/v1/findings/summary
POST  /api/v1/findings/ingest
PATCH /api/v1/findings/{finding_id}
```

### System

```http
GET  /api/v1/system/scanner-config
PUT  /api/v1/system/scanner-config
POST /api/v1/system/reset-inventory
GET  /api/v1/system/fingerprint-datasets
POST /api/v1/system/fingerprint-datasets/{dataset_key}/refresh
GET  /api/v1/system/tplink-deco
PUT  /api/v1/system/tplink-deco
POST /api/v1/system/tplink-deco/test
POST /api/v1/system/tplink-deco/sync
```

## WebSocket Events

WebSocket endpoint:

```text
ws://localhost:8000/ws/events
```

All messages use the envelope format `{"event": "<type>", "data": {...}}`.

### `scan_progress`

Emitted throughout a running scan as each stage completes or progresses.

```json
{
  "event": "scan_progress",
  "data": {
    "job_id": "12345678-1234-1234-1234-1234567890ab",
    "stage": "investigation",
    "progress": 0.65,
    "message": "Investigated 13/20 hosts",
    "hosts_found": 20,
    "hosts_port_scanned": 20,
    "hosts_fingerprinted": 13,
    "hosts_deep_probed": 10,
    "hosts_investigated": 13,
    "assets_created": 2,
    "assets_updated": 11
  }
}
```

| Field | Type | Description |
|---|---|---|
| `job_id` | string | UUID of the scan job |
| `stage` | string | Current pipeline stage: `discovery`, `port_scan`, `investigation`, `persist` |
| `progress` | float | Approximate 0–1 progress fraction |
| `message` | string | Human-readable status description |
| `hosts_found` | int | Total hosts discovered in Stage 1 |
| `hosts_port_scanned` | int | Hosts that completed Stage 2 |
| `hosts_fingerprinted` | int | Hosts that completed Stage 3 |
| `hosts_deep_probed` | int | Hosts that received deep probes (Stage 4) |
| `hosts_investigated` | int | Hosts that completed full investigation |
| `assets_created` | int | New assets created so far this scan |
| `assets_updated` | int | Existing assets updated so far this scan |
| `current_host` | string \| null | IP of the host currently being investigated |

### `device_discovered`

Emitted when a previously unknown host is first persisted to inventory.

```json
{
  "event": "device_discovered",
  "data": {
    "job_id": "12345678-...",
    "stage": "investigation",
    "ip": "192.168.1.42",
    "mac": "aa:bb:cc:dd:ee:ff",
    "hostname": "mydevice.local",
    "device_class": "workstation"
  }
}
```

### `device_updated`

Emitted when an existing asset is updated with new scan data.

```json
{
  "event": "device_updated",
  "data": {
    "job_id": "12345678-...",
    "stage": "investigation",
    "ip": "192.168.1.42",
    "hostname": "mydevice.local"
  }
}
```

### `device_investigated`

Emitted when the AI agent completes analysis for a host (only when AI analysis is enabled).

```json
{
  "event": "device_investigated",
  "data": {
    "job_id": "12345678-...",
    "ip": "192.168.1.42",
    "device_class": "router",
    "vendor": "MikroTik",
    "confidence": 0.88
  }
}
```

### `scan_complete`

Emitted once when a scan finishes (regardless of outcome).

```json
{
  "event": "scan_complete",
  "data": {
    "job_id": "12345678-...",
    "targets": "192.168.1.0/24",
    "profile": "balanced",
    "hosts_scanned": 20,
    "hosts_up": 20,
    "new_assets": 2,
    "changed_assets": 11,
    "offline_assets": 1,
    "total_open_ports": 87,
    "ai_analyses_completed": 18,
    "duration_seconds": 142.3
  }
}
```

### `heartbeat`

Emitted periodically to keep idle connections alive. No data fields.

```json
{"event": "heartbeat", "data": {}}
```

## Data Model Themes

The backend stores and exposes more than a flat asset table.

Examples:

- ports
- asset history
- findings
- evidence
- probe runs
- passive observations
- fingerprint hypotheses
- lifecycle records
- audit logs
- autopsy traces

## Configuration and Integrations

The backend exposes admin APIs for:

- scanner settings
- SNMP and passive settings
- fingerprint datasets
- backup policy
- integration event catalogs
- plugin registry
- TP-Link Deco module

## Example Token Request

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin&password=changeme'
```

## TypeScript Example

The frontend uses typed API clients. Example response shape without `any`:

```ts
type ScanProgressEvent = {
  event: 'scan_progress';
  data: {
    job_id: string;
    stage: string;
    message: string;
    discovered_hosts?: number;
    investigated_hosts?: number;
  };
};
```

## Related Docs

- [Architecture](../architecture.md)
- [Frontend Dashboard Guide](./frontend-dashboard.md)
- [Scanner Guide](./scanner.md)
- [Settings Reference](./settings-reference.md)
