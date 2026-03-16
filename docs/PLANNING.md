# Argus — Application Development Planning

> **Argus Panoptes** was the hundred-eyed giant of Greek mythology — all-seeing, always watching. This project borrows his name for the same reason: total visibility into every device on your network.

---

## Table of Contents

1. [Vision & Goals](#1-vision--goals)
2. [Architecture Overview](#2-architecture-overview)
3. [Technology Stack](#3-technology-stack)
4. [Data Model](#4-data-model)
5. [API Design](#5-api-design)
6. [Discovery Engine](#6-discovery-engine)
7. [Frontend & UX](#7-frontend--ux)
8. [Feature Roadmap](#8-feature-roadmap)
9. [Docker Architecture](#9-docker-architecture)
10. [Security Model](#10-security-model)
11. [Development Workflow](#11-development-workflow)
12. [Testing Strategy](#12-testing-strategy)
13. [Contributing Guidelines](#13-contributing-guidelines)
14. [Open Questions & Decisions Log](#14-open-questions--decisions-log)

---

## 1. Vision & Goals

### What Argus Is

Argus is a self-hosted, open-source network asset discovery and inventory platform designed for home labs, small offices, and enthusiast environments. It brings enterprise-grade visibility — the kind you'd find in tools like SolarWinds, Auvik, or Netbox — to anyone running a Docker host, at zero license cost.

### Core Principles

**Automatic over manual.** The system should discover and update your network inventory with minimal configuration. You declare your subnets; Argus handles the rest.

**Map first, list second.** The primary interface is a live topology map, not a table. Tables are for drill-down. Humans understand networks spatially.

**Change is a first-class citizen.** Every change to every asset is recorded. You should always be able to answer "when did that device first appear?" and "what ports were open last Tuesday?"

**Runs on any Docker host.** A single `docker compose up` should get you from zero to a running instance. No Kubernetes, no cloud dependencies, no license servers.

**API first.** Every capability exposed in the UI is also available via a documented REST API. This enables automation, integrations, and scripting.

### Non-Goals (v1)

- Cloud/SaaS hosting
- Managing more than a few thousand devices (scale is not the initial focus)
- Replacing dedicated vulnerability scanners (Nessus, OpenVAS) — integrate with them, don't replicate them
- Mobile-native apps (responsive web is sufficient)

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         User's Browser                          │
│                     Next.js Frontend (React)                    │
│         Dashboard │ Topology Map │ Asset Inventory │ Settings   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTP/REST + WebSocket
┌──────────────────────────▼──────────────────────────────────────┐
│                     FastAPI Backend (Python)                     │
│    /api/v1/assets  /api/v1/scans  /api/v1/topology  /ws/events  │
│              JWT Auth │ CORS │ OpenAPI Docs                      │
└──────┬───────────────────────────────────────────┬──────────────┘
       │ SQLAlchemy async                          │ Redis pub/sub
┌──────▼──────────┐                    ┌───────────▼──────────────┐
│   PostgreSQL    │                    │    Redis (Celery Broker)  │
│  Assets, Ports  │                    │    Task Queue + WS Cache  │
│  Topology Links │                    └───────────┬──────────────┘
│  Scan Jobs      │                                │ task dispatch
│  Audit History  │                    ┌───────────▼──────────────┐
└─────────────────┘                    │   Scanner Worker (Celery) │
                                       │  nmap │ arp-scan │ scapy  │
                                       │  SNMP │ MAC lookup         │
                                       │  Passive ARP listener     │
                                       └──────────────────────────┘
```

### Key Architectural Decisions

**Separation of scanner from API.** The scanner worker runs as an independent container with elevated network capabilities (`NET_RAW`, `NET_ADMIN`). This keeps the attack surface of the API process minimal — it never touches raw sockets. The analogy: the API is your front-desk receptionist; the scanner is the field agent. They communicate via the task queue (Redis), not direct function calls.

**Async all the way down.** FastAPI + asyncpg + SQLAlchemy async means the API can handle many concurrent WebSocket connections and database queries without thread-per-request overhead. Think of it as event-driven I/O: instead of blocking while waiting for a DB response, the process handles other requests, then resumes when the data arrives.

**PostgreSQL as the single source of truth.** Redis is ephemeral — cache and queue only. Every persisted state lives in Postgres. This makes backup/restore trivial: snapshot the Postgres volume.

**Network topology as a graph.** The `topology_links` table is an adjacency list — the same structure used by graph databases, but stored relationally. This allows standard SQL queries for neighbor lookup while keeping the data model simple. For the frontend, the graph is serialized as Cytoscape.js elements (nodes + edges), which maps 1:1 to the UI rendering model.

---

## 3. Technology Stack

### Backend

| Concern | Choice | Rationale |
|---|---|---|
| Web framework | FastAPI 0.111 | Async-native, automatic OpenAPI, Python type hints as schema |
| ORM | SQLAlchemy 2.0 async | Industry standard, excellent migration tooling via Alembic |
| Database | PostgreSQL 16 | JSONB for flexible custom fields, pg_trgm for fast text search |
| Task queue | Celery + Redis | Proven, rich ecosystem, supports periodic (beat) scheduling |
| Network discovery | python-nmap, scapy | nmap for active scanning, scapy for raw packet passive listening |
| SNMP | pysnmp | Pure Python, async-capable, v2c and v3 support |
| Auth | python-jose + passlib | JWT with bcrypt — stateless, standard |
| Logging | structlog | Structured JSON logs — machine-parseable and human-readable |

### Frontend

| Concern | Choice | Rationale |
|---|---|---|
| Framework | Next.js 14 (App Router) | RSC for static pages, client components for interactive map |
| Language | TypeScript strict | Types eliminate entire classes of bugs, especially around API shapes |
| Styling | Tailwind CSS | Utility-first — fast iteration, no CSS file management |
| Components | shadcn/ui | Unstyled accessible primitives, composable, no vendor lock-in |
| Topology map | Cytoscape.js | Purpose-built graph rendering library — handles thousands of nodes, rich layout algorithms |
| Data fetching | TanStack Query v5 | Intelligent caching, background refresh, loading/error states |
| State | Zustand | Minimal, no boilerplate — topology selection state, filter state |
| Charts | Recharts | Declarative React charts for dashboard metrics |
| Real-time | Native WebSocket + Zustand | WS events update the Zustand store; React re-renders are automatic |

### Infrastructure

| Concern | Choice | Rationale |
|---|---|---|
| Container runtime | Docker + Compose | Universal, no Kubernetes complexity for home lab scale |
| Reverse proxy (optional) | Caddy or nginx | TLS termination if exposing beyond localhost |
| CI/CD | GitHub Actions | Free for public repos, integrates with the GitHub remote |

---

## 4. Data Model

### Entity Relationship Summary

```
User
  │
  └── (creates) ScanJob
                  │
                  └── (discovers/updates) Asset ──< Port
                                            │
                                            ├──< AssetTag
                                            ├──< AssetHistory  (append-only log)
                                            │
Asset >── TopologyLink ──< Asset  (directed adjacency list for graph)
```

### Asset

The core entity. Represents one network-addressable device.

- `ip_address` — primary natural key (unique). IPv4 or IPv6.
- `mac_address` — used for vendor OUI lookup and device identity across IP changes (DHCP reassignment).
- `hostname` — reverse DNS lookup or user-set label.
- `vendor` — derived from MAC OUI (e.g., "Apple", "Ubiquiti Networks").
- `os_name` / `os_version` — nmap OS fingerprint output.
- `device_type` — user-settable classification: router, switch, server, workstation, IoT, printer.
- `status` — `online` | `offline` | `unknown` — updated on every scan cycle.
- `custom_fields` — JSONB column for arbitrary user metadata (e.g., `{"location": "basement", "owner": "media server"}`).
- `first_seen` / `last_seen` — timestamp tracking. These power "new device" alerts and staleness detection.

### AssetHistory

Append-only change log. Every time a scan produces a diff for an asset, a record is written with:
- `change_type` — `discovered` | `port_opened` | `port_closed` | `os_changed` | `hostname_changed` | `offline` | `online`
- `diff` — JSONB `{field: {old: x, new: y}}` — human-readable and machine-queryable change record.

This is the audit trail. It answers questions like "when did this server start exposing port 22?" without needing time-series infrastructure.

### TopologyLink

Directed adjacency list for the network graph. Source → Target with metadata:
- `link_type` — `ethernet` | `wifi` | `vlan` | `vpn`
- `vlan_id` — for VLAN-aware topology (populated via SNMP from managed switches)

Topology links are inferred from: ARP tables (who talks to whom), SNMP interface tables (physical adjacency), and user manual curation.

### ScanJob

Represents one execution of the discovery engine.
- `targets` — CIDR string or comma-separated IPs.
- `scan_type` — `full` (OS + ports + services) | `quick` (ping + top 100 ports) | `ports` (port scan only) | `snmp`.
- `status` — state machine: `pending` → `running` → `done` | `failed`.
- `result_summary` — JSONB with counts: `{hosts_scanned: 254, new: 3, changed: 7, offline: 2}`.

---

## 5. API Design

Base path: `/api/v1/`

All endpoints return JSON. Authentication via `Authorization: Bearer <token>` header.

### Assets

```
GET    /assets/              List assets (supports ?search=, ?status=, ?tag=)
GET    /assets/{id}          Get single asset with ports and tags
PATCH  /assets/{id}          Update mutable fields (hostname, notes, device_type, custom_fields)
DELETE /assets/{id}          Remove an asset from inventory
GET    /assets/{id}/history  Full change history for an asset
GET    /assets/{id}/ports    Port list for an asset
```

### Scans

```
GET    /scans/               List recent scan jobs
POST   /scans/trigger        Enqueue a manual scan { targets, scan_type }
GET    /scans/{id}           Get scan job status and result_summary
DELETE /scans/{id}           Cancel a pending scan
```

### Topology

```
GET    /topology/graph       Full graph as Cytoscape.js elements { nodes[], edges[] }
POST   /topology/links       Manually add a topology link
DELETE /topology/links/{id}  Remove a topology link
```

### Auth

```
POST   /auth/token           Login (OAuth2 password flow) → access_token
GET    /auth/me              Current user info
POST   /auth/users           Create user (admin only)
```

### WebSocket

```
WS /ws/events                Real-time event stream
```

Event payload schema:

```json
{
  "event": "device_discovered | scan_progress | device_status_change | heartbeat",
  "data": { ... }
}
```

### API Versioning Strategy

The `/api/v1/` prefix allows a future `/api/v2/` without breaking existing clients. A thin compatibility shim can translate v2 requests to v1 semantics if needed.

---

## 6. Discovery Engine

### Active Scanning (nmap)

The primary discovery mechanism. nmap is invoked as a subprocess via `python-nmap`. The default scan profile (`-sV -O --osscan-guess -T4`) provides:
- Host discovery (ping sweep)
- Port scanning (top 1000 TCP ports)
- Service version detection (`-sV`)
- OS fingerprinting (`-O`)
- Timing template 4 (aggressive but not intrusive on LANs)

For quick scans: `-sn -T4` (ping only, no ports) — useful for high-frequency "who's online" checks.

### Passive ARP Listening (scapy)

A long-running scapy listener captures ARP broadcasts on the local segment. Every time a device sends an ARP request or reply, Argus records it. This gives near-real-time detection of new devices joining the network without active scanning — like having a doorbell that rings whenever a new device shows up.

This requires `NET_RAW` capability (granted in `docker-compose.yml`) and runs only on the same broadcast domain as the Docker host.

### SNMP Polling (Phase 2)

For managed switches and routers, SNMP provides data unavailable from nmap:
- Physical port adjacency (which switch port is each device on)
- Interface statistics (bytes in/out, errors, utilization)
- ARP tables (enables topology inference for routed segments)
- System name, location, description

SNMP v3 (auth + privacy) is preferred for security; v2c with community string as fallback.

### Asset Upsert Logic

On every scan, the pipeline:
1. Runs nmap, receives a list of normalized host dicts.
2. For each host, queries the DB by `ip_address`.
3. If not found: create new `Asset`, write `AssetHistory(change_type="discovered")`, broadcast `device_discovered` WS event.
4. If found: diff the new data against stored data. For each changed field, write an `AssetHistory` record. Update the `Asset` row.
5. For assets in the DB that were NOT in the scan results: mark `status=offline`, write history.
6. Update `ScanJob.status = "done"` with result summary.

This diff-then-persist pattern is the same approach used by infrastructure tools like Terraform: compute the delta, apply only what changed.

### MAC Vendor Lookup

The `mac-vendor-lookup` library resolves the first 3 octets (OUI) of a MAC address to a manufacturer name. This runs locally against a bundled IEEE database — no external API calls. Refreshable by updating the package.

---

## 7. Frontend & UX

### Page Structure

```
/ (redirect to /dashboard)
/dashboard          — Overview: asset counts, online/offline ratio, recent scan activity, new devices
/topology           — Interactive network map (Cytoscape.js)
/assets             — Searchable, filterable inventory table
/assets/[id]        — Asset detail: info, ports, history timeline, edit form
/scans              — Scan job history and manual trigger
/settings           — Scan configuration, SNMP settings, notification rules, user management
```

### Topology Map Design

The topology page is the flagship feature. Design goals:

- **Force-directed layout by default** (Cytoscape fcose algorithm) — devices that communicate cluster together naturally, like a self-organizing org chart.
- **Node appearance encodes status** — online = solid color, offline = muted/dashed border, unknown = gray.
- **Device type icons** — routers, switches, servers, and workstations get distinct icons (SVG, inlined).
- **Click to inspect** — clicking a node opens a slide-over panel with asset details without leaving the map.
- **Filter by VLAN / subnet** — show only devices in a selected segment; rest are dimmed.
- **Pin nodes** — drag and pin important devices (gateway, NAS) to fixed positions. Positions saved to `custom_fields`.
- **Real-time updates** — WebSocket events animate new nodes appearing and status changes without full page reload.

### Dashboard Widgets

- Total assets / online count / offline count (stat cards)
- New devices in last 24h / 7d
- Last scan time and result summary
- Top open ports chart (bar chart via Recharts)
- Recent activity feed (last 20 AssetHistory events)

### State Management Pattern

TanStack Query handles all server state (assets, scans, topology graph) with automatic background refetching. Zustand holds UI-only state: selected asset ID, topology filter settings, WebSocket connection instance. The separation mirrors the model-view split: Query = model, Zustand = view state.

---

## 8. Feature Roadmap

### Phase 1 — Foundation (MVP)

Target: working end-to-end discovery → inventory → topology map.

- [ ] Docker Compose stack fully operational (db, redis, backend, scanner, frontend)
- [ ] nmap active scanning with configurable CIDR targets
- [ ] Asset upsert pipeline with change detection
- [ ] AssetHistory audit trail
- [ ] REST API: assets, scans, topology, auth
- [ ] WebSocket real-time events
- [ ] Frontend: Dashboard, Asset list, Asset detail
- [ ] Topology map with Cytoscape.js (basic force layout)
- [ ] Manual scan trigger from UI
- [ ] JWT authentication (single admin user)
- [ ] MAC vendor lookup
- [ ] Scheduled scans via Celery Beat

### Phase 2 — Enrichment

Target: richer data, smarter topology, notifications.

- [ ] SNMP v2c/v3 polling for managed devices
- [ ] Passive ARP listener (scapy)
- [ ] DNS/DHCP log ingestion (optional, parser for common formats)
- [ ] VLAN-aware topology (from SNMP interface tables)
- [ ] Topology link inference from ARP tables
- [ ] Webhook notifications (new device, device offline > N minutes)
- [ ] Email notifications (SMTP)
- [ ] Asset tagging UI
- [ ] Custom fields editor
- [ ] Export inventory to CSV

### Phase 3 — Enterprise Features

Target: multi-user, alerting rules engine, integrations.

- [ ] Multi-user RBAC (admin, operator, read-only roles)
- [ ] Alert rules engine: configurable conditions → actions
- [ ] Vulnerability scan integration (Nessus XML import, OpenVAS)
- [ ] Network segmentation visualization (subnets as swim lanes)
- [ ] REST API key authentication (in addition to JWT)
- [ ] Full API key management UI
- [ ] Audit log UI (filter by asset, user, change type)
- [ ] PDF / HTML report export
- [ ] Alembic database migrations (replacing create_all)
- [ ] Prometheus metrics endpoint
- [ ] Optional Grafana dashboard (pre-built JSON)

### Phase 4 — Advanced

- [ ] Configuration backup (SSH-based: Cisco, Juniper, MikroTik, OpenWRT)
- [ ] Layer 2 diagram (CDP/LLDP neighbor discovery via SNMP)
- [ ] Wireless client association tracking (via access point SNMP)
- [ ] Ansible inventory export
- [ ] Terraform resource export
- [ ] Plugin system for custom discovery modules

---

## 9. Docker Architecture

### Services

| Service | Image | Purpose | Network |
|---|---|---|---|
| `db` | postgres:16-alpine | Primary data store | internal |
| `redis` | redis:7-alpine | Celery broker + WS cache | internal |
| `backend` | argus-backend (custom) | FastAPI REST API + WS | host mode |
| `scanner` | argus-scanner (custom) | Celery worker + Beat | host mode |
| `frontend` | argus-frontend (custom) | Next.js SSR + static | bridge |

### Why `network_mode: host` for backend and scanner?

Network scanning from within a Docker bridge network is constrained — the container can only see its own subnet. Host networking mode lets the scanner container see the same network interfaces as the Docker host, enabling scanning of LAN subnets directly. This is a necessary trade-off for a tool whose core job is network discovery.

### Volumes

- `postgres_data` — persistent Postgres data directory. Back this up.
- `redis_data` — Redis persistence (AOF or RDB). Optional but prevents losing queued jobs on restart.

### Capabilities

`NET_RAW` and `NET_ADMIN` are granted to the backend and scanner containers. These are required for:
- ICMP ping (host discovery)
- Raw socket ARP listening (passive discovery)
- nmap's SYN scan mode (faster and more accurate than connect scan)

These capabilities should not be granted to the frontend or database containers.

### Development vs Production

`docker-compose.dev.yml` overrides the production compose file with:
- Hot reload (uvicorn `--reload`, Next.js `dev` mode)
- Source volume mounts (edit code without rebuilding)
- More verbose logging

Production build uses multi-stage Dockerfiles for minimal image sizes.

---

## 10. Security Model

### Threat Model for Home Lab Context

Argus runs on a private network and is not exposed to the internet by default. The primary threats are:
1. Unauthorized access by other devices on the LAN.
2. Accidental exposure via port forwarding or VPN misconfiguration.
3. Scanner container escape (elevated capabilities).

### Mitigations

**Authentication.** All API endpoints require a valid JWT. The WebSocket endpoint should also validate token on connection. The default admin credentials in `.env.example` are intentionally weak — the setup script prompts the user to change them.

**Container isolation.** Only the scanner and backend containers receive elevated capabilities. The database and frontend run with default (unprivileged) settings.

**No outbound calls by default.** Argus does not phone home, send telemetry, or require internet access. MAC OUI lookups use a bundled local database. This is both a privacy and reliability feature.

**HTTPS (optional but recommended).** For any non-localhost exposure, place Caddy or nginx in front as a TLS-terminating reverse proxy. Caddy's automatic HTTPS via Let's Encrypt makes this nearly effortless.

**Future: network policy.** In Phase 3, document a Docker network policy that restricts inter-container communication to only necessary paths (frontend → backend, backend → db, scanner → redis, etc.).

---

## 11. Development Workflow

### Getting Started

```bash
git clone https://github.com/joelmale/argus.git
cd argus
./scripts/setup.sh
```

The setup script copies `.env.example` → `.env`, builds containers, and starts the stack.

### Development Mode

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up
```

Source directories are volume-mounted; changes to Python or TypeScript files reload automatically.

### Backend-Only Development

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Start Postgres and Redis via Docker, then:
uvicorn app.main:app --reload
```

API docs available at `http://localhost:8000/docs` (Swagger UI) and `/redoc`.

### Frontend-Only Development

```bash
cd frontend
npm install
npm run dev
# Set NEXT_PUBLIC_API_URL=http://localhost:8000 in .env.local
```

### Database Migrations (Phase 3 target)

Phase 1 uses SQLAlchemy's `create_all` for simplicity. Before any production deployment, migrate to Alembic:

```bash
alembic init alembic
# Edit alembic.ini and env.py
alembic revision --autogenerate -m "initial schema"
alembic upgrade head
```

### Branch Strategy

- `main` — production-ready, tagged releases only
- `develop` — integration branch, all feature branches merge here
- `feature/xxx` — individual feature work
- `fix/xxx` — bug fixes

---

## 12. Testing Strategy

### Backend

**Unit tests** (pytest + pytest-asyncio): test individual functions in isolation — scanner normalization logic, change detection diffing, security utilities.

**Integration tests**: spin up a test Postgres instance (pytest fixtures), test the full API request → DB → response cycle. Use `httpx.AsyncClient` with the FastAPI test client.

**Scanner tests**: mock nmap output using fixture XML files (nmap supports `--xml` output; python-nmap can parse files). This avoids needing real network access in CI.

Target: >80% coverage on backend business logic.

### Frontend

**Unit tests** (Vitest + React Testing Library): test individual components — asset card rendering, filter logic, topology data transformations.

**E2E tests** (Playwright, Phase 2): smoke test the critical user journey — login → view dashboard → trigger scan → see result.

### CI

GitHub Actions runs on every push to `main` and `develop`:
1. Backend: ruff lint + pytest
2. Frontend: ESLint + TypeScript type-check
3. Docker: build both images (validates Dockerfile syntax and dependency installation)

---

## 13. Contributing Guidelines

### Code Style

**Python**: ruff for linting and formatting (replaces black + isort + flake8). Configuration in `pyproject.toml`.

**TypeScript**: ESLint + Prettier. Configuration in `.eslintrc.json` and `.prettierrc`.

**Commits**: conventional commit format (`feat:`, `fix:`, `chore:`, `docs:`, `refactor:`). This enables automatic changelog generation.

### Pull Request Process

1. Branch from `develop`.
2. Write tests for new functionality.
3. Ensure CI passes.
4. PR description should explain *why*, not just *what*.
5. At least one review before merge to `develop`.

### Issue Labels

- `discovery` — related to the scanner/discovery engine
- `frontend` — UI/UX issues
- `api` — backend API issues
- `data-model` — schema changes
- `docker` — container/deployment issues
- `good first issue` — suitable for new contributors

---

## 14. Open Questions & Decisions Log

This section tracks architectural decisions and open questions as the project evolves. Keeping a decision log is like version-controlling your reasoning — you can always look back and understand *why* something was built a certain way.

### Decided

| Date | Decision | Rationale |
|---|---|---|
| 2026-03 | Python + FastAPI for backend | Richest network library ecosystem; async-native |
| 2026-03 | PostgreSQL over SQLite | JSONB, pg_trgm, proper concurrent write support; SQLite too limited for multi-container |
| 2026-03 | Cytoscape.js for topology | Purpose-built graph rendering; vis.js considered but Cytoscape has better TypeScript types and layout algorithm ecosystem |
| 2026-03 | Celery over APScheduler | APScheduler considered for simplicity; Celery chosen for distributed worker potential and richer task introspection |
| 2026-03 | network_mode: host for scanner | Required for LAN-visible scanning; bridge mode restricts to container subnet only |

### Open Questions

- **Topology inference automation**: how much should Argus auto-infer topology links vs requiring manual curation? SNMP ARP tables help but are unreliable across routed segments.
- **IPv6 support**: nmap supports IPv6, but link-local addresses complicate the `ip_address` as unique key assumption. Defer to Phase 2?
- **Multi-network-interface support**: Docker hosts with multiple NICs (e.g., separate management and data networks) — how to configure which interface the scanner listens on?
- **Licensing**: MIT chosen tentatively for maximum permissiveness. Should we consider AGPL to prevent commercial SaaS forks without contribution? (Common in open-source infrastructure tools.)
- **Plugin architecture**: Phase 4 envisions a plugin system for custom discovery modules. Python entry points vs. subprocess-based plugins vs. WASM — trade-offs TBD.
