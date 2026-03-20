# Argus

Network discovery, inventory, fingerprinting, topology mapping, and homelab operations visibility.

[![CI](https://github.com/joelmale/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/joelmale/argus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Argus is a self-hosted network inventory platform for home labs and small environments. It actively scans your network, enriches devices with fingerprinting evidence, keeps an audit trail of changes, exposes a REST API and WebSocket stream, and provides a modern dashboard for assets, scans, findings, topology, backups, and settings.

## What Argus Does Today

- Active discovery with `nmap`
- Passive observations from ARP and imported DHCP/DNS logs
- Asset inventory with ports, tags, notes, custom fields, history, findings, AI analysis, evidence, and autopsy traces
- Evidence-driven fingerprinting with:
  - MAC OUI/vendor data
  - HTTP/TLS/SSH/SNMP hints
  - passive observations
  - instant-win Nmap fingerprints
  - optional Ollama synthesis
  - optional allowlisted internet lookup
- Topology graph with Cytoscape.js
- Scan scheduling and live scan progress over WebSocket
- JWT auth with `admin` / `viewer` roles
- Admin-managed API keys
- Audit log and asset history
- Findings ingestion and summary views
- Config backup workflows for supported SSH-based devices
- Inventory exports:
  - CSV
  - JSON
  - Ansible inventory
  - Terraform data
  - HTML/JSON reports
- Fingerprint dataset registry and refresh controls
- TP-Link Deco local-portal module with:
  - node and client sync
  - log collection from the system-log feed
  - parsed health/recommendation analysis

## Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 16, React 19, TypeScript, Tailwind CSS |
| Backend | FastAPI, SQLAlchemy async, Pydantic |
| Database | PostgreSQL 16 |
| Queue / Events | Redis, Celery, Redis pub/sub |
| Discovery | nmap, scapy, pysnmp |
| Topology UI | Cytoscape.js |
| Runtime | Docker Compose |

## Quick Start

```bash
git clone https://github.com/joelmale/argus.git
cd argus
npm run setup
```

Then open:

- Frontend: `http://localhost:3000`
- API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`

Default first-run credentials:

- username: `admin`
- password: `changeme`

Change them after first login.

## Local Development

### Recommended

Use the Docker-first workflow:

```bash
npm run dev
```

Background start:

```bash
npm run dev:up
```

Stop:

```bash
npm run dev:down
```

Logs:

```bash
npm run dev:logs
```

### Build / Rebuild

Normal `dev` commands do not force a rebuild.

```bash
npm run dev:build
npm run dev:rebuild
```

### Common Commands

```bash
npm run lint
npm run lint:backend
npm run lint:frontend

npm run test
npm run test:backend
npm run test:backend:cov
npm run test:backend:cov:enforced

npm run type-check
npm run build
npm run verify

npm run db:migrate
npm run dev:ps
```

### Host-Local Backend Checks

If you want to run backend checks outside Docker:

```bash
pip install -r backend/requirements-dev.txt
npm run lint:backend:local
npm run test:backend:local
npm run test:backend:cov:local
```

## Docker Architecture

Base compose file:

- `docker-compose.yml`
  - production-oriented baseline
  - Postgres, Redis, backend, scanner, frontend

Dev override:

- `docker-compose.dev.yml`
  - source mounts
  - frontend dev mode
  - backend dev image with test/lint tooling
  - scanner on host networking for local-network visibility

Important behavior:

- the dev backend includes `pytest`, `ruff`, and coverage tooling
- the production backend image does not include test-only tooling
- the scanner runs with `NET_RAW` / `NET_ADMIN`
- in dev, the scanner uses host networking so active and passive discovery can see the real LAN

## Configuration

Bootstrap config comes from `.env`. Day-to-day scanner behavior is now managed primarily through the Settings UI.

Start from:

```bash
cp .env.example .env
```

Important `.env` values:

- app and auth
  - `APP_SECRET_KEY`
  - `ADMIN_USERNAME`
  - `ADMIN_PASSWORD`
- database and redis
  - `DATABASE_URL`
  - `REDIS_URL`
- initial scanner defaults
  - `SCANNER_DEFAULT_TARGETS`
  - `SCANNER_DEFAULT_PROFILE`
  - `SCANNER_INTERVAL_MINUTES`
- AI
  - `AI_BACKEND`
  - `OLLAMA_BASE_URL`
  - `OLLAMA_MODEL`
  - `ANTHROPIC_API_KEY`
- notifications
  - `NOTIFY_WEBHOOK_URL`
  - SMTP values

### Settings UI

The Settings screen is now grouped by function and includes live configuration for:

- scanner configuration
- passive ARP and SNMP settings
- AI fingerprint synthesis and internet lookup controls
- fingerprint dataset registry and updates
- backup policy
- users and API keys
- audit log
- TP-Link Deco module

Notable scanner settings available in the UI:

- default targets
- auto-detect local subnet
- default profile
- interval
- concurrent hosts
- passive ARP enablement and interface
- SNMP v2c / v3 settings
- AI fingerprinting controls
- internet lookup budget and allowlist

## Core Product Areas

### Assets

The asset detail view includes:

- overview
- ports
- findings
- evidence
- probe runs
- passive timeline
- AI analysis
- fingerprint hypotheses
- lookup provenance
- lifecycle status
- wireless associations
- config backups
- tags and metadata
- discovery autopsy trace

Manual actions on an asset include:

- AI lookup
- targeted port scan
- metadata edits
- backup actions

### Scans

Argus supports:

- manual scan trigger
- scheduled scans via Celery Beat
- live progress updates
- expanded active-scan detail view in the UI
- overlap protection for scheduled scans

### Fingerprinting Engine

Argus now uses a dedicated fingerprinting/evidence model rather than a single guess path.

Evidence sources include:

- MAC vendor datasets
- Nmap OS/service output
- SSH/HTTP/TLS/SNMP probe data
- passive observations
- instant-win fingerprints for common homelab devices
- optional Ollama synthesis
- optional internet lookup

Argus also tracks:

- fingerprint hypotheses
- internet lookup provenance
- lifecycle records
- asset autopsies

### Findings and Risk

Argus supports:

- findings ingestion from external tools
- finding summary dashboard
- finding status updates
- lifecycle/EOL records
- local risk enrichment tied to fingerprinting and version data

### Backups and Exports

Supported capabilities include:

- SSH-based config backup flows for supported platforms
- backup target management
- backup diffs
- restore-assist guidance
- scheduled backup policy
- inventory exports and reports

### TP-Link Deco Module

The Deco module is optional and managed from Settings.

Current capabilities:

- local-portal login using the owner password
- discovery of Deco nodes and connected clients
- ingestion of Deco observations into assets and passive timeline
- system-log retrieval from the live paged log feed
- parsed recommendation engine for recurring mesh / roaming / steering issues
- downloadable local log copy from the Argus UI

## API Overview

Base path: `/api/v1`

Main route groups:

- `/auth`
  - login
  - current user
  - users
  - API keys
- `/assets`
  - list/detail/update
  - exports
  - reports
  - AI lookup
  - port scan
  - backups
- `/scans`
  - list
  - trigger
  - log ingestion
- `/topology`
  - graph
  - manual links
- `/findings`
  - list
  - summary
  - ingest
- `/system`
  - scanner settings
  - backup policy
  - plugins
  - integration events
  - dataset registry
  - TP-Link Deco module

Real-time events:

- WebSocket: `/ws/events`

API auth options:

- JWT bearer token
- `X-API-Key`

## Frontend Pages

Current primary views:

- `/dashboard`
- `/assets`
- `/assets/[id]`
- `/topology`
- `/scans`
- `/findings`
- `/settings`
- `/login`

## Test and Coverage Status

Backend coverage is measured and enforced in CI.

Current enforced floor:

- backend coverage threshold: `55%`

Useful commands:

```bash
npm run test:backend:cov
npm run test:backend:cov:enforced
```

Current test strategy emphasizes:

- API route regression tests
- scan pipeline and fingerprinting paths
- integrations and module adapters
- persistence / serialization bugs found during real use

## Project Structure

High-signal directories:

- `backend/app/api/`
- `backend/app/scanner/`
- `backend/app/fingerprinting/`
- `backend/app/modules/`
- `backend/app/db/`
- `backend/alembic/`
- `frontend/src/app/`
- `frontend/src/components/`
- `docs/`

## Documentation

- Roadmap and architecture: [docs/PLANNING.md](/Users/JoelN/Coding/argus/docs/PLANNING.md)
- Fingerprinting engine plan: [docs/FINGERPRINTING_ENGINE_PLAN.md](/Users/JoelN/Coding/argus/docs/FINGERPRINTING_ENGINE_PLAN.md)
- Plugin packaging: [docs/plugins/README.md](/Users/JoelN/Coding/argus/docs/plugins/README.md)

## Notes

- The scanner can auto-detect the local subnet, but you should still confirm the effective targets in Settings before your first real scan.
- Consumer mesh/AP gear varies a lot in what it exposes. SNMP-capable infrastructure gives better topology and wireless visibility than app-only consumer devices.
- The Deco module currently treats the live paged system-log API as the authoritative source and builds its own exportable copy from that feed.

## License

MIT
