# Argus

Network discovery, inventory, fingerprinting, topology mapping, and homelab operations visibility.

[![PR Checks](https://github.com/joelmale/argus/actions/workflows/pr-checks.yml/badge.svg)](https://github.com/joelmale/argus/actions/workflows/pr-checks.yml)
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
cp .env.example .env
npm run setup
```

Then open:

- Frontend: `http://localhost:3000`
- API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`

On first run, Argus prompts you to create the initial admin account in the UI.

## Development

For local development and operational details, use [docs/getting-started.md](/Users/JoelN/Coding/argus/docs/getting-started.md).

Most common commands:

```bash
npm run dev
npm run dev:up
npm run dev:down
npm run dev:logs
npm run verify
```

## Configuration

Development uses `.env`. The production compose stack reads [.env.production](/Users/JoelN/Coding/argus/.env.production) as a template and expects secrets and deployment-specific values to be overridden in your deployment platform.

## Documentation

- Getting started: [docs/getting-started.md](/Users/JoelN/Coding/argus/docs/getting-started.md)
- Architecture: [docs/architecture.md](/Users/JoelN/Coding/argus/docs/architecture.md)
- Troubleshooting: [docs/troubleshooting.md](/Users/JoelN/Coding/argus/docs/troubleshooting.md)
- Scanner guide: [docs/guides/scanner.md](/Users/JoelN/Coding/argus/docs/guides/scanner.md)
- Scan profiles: [docs/guides/scan-profiles.md](/Users/JoelN/Coding/argus/docs/guides/scan-profiles.md)
- Fingerprinting guide: [docs/guides/fingerprinting.md](/Users/JoelN/Coding/argus/docs/guides/fingerprinting.md)
- Settings reference: [docs/guides/settings-reference.md](/Users/JoelN/Coding/argus/docs/guides/settings-reference.md)
- Backend API: [docs/guides/backend-api.md](/Users/JoelN/Coding/argus/docs/guides/backend-api.md)
- Frontend dashboard: [docs/guides/frontend-dashboard.md](/Users/JoelN/Coding/argus/docs/guides/frontend-dashboard.md)
- CI/CD and security: [docs/guides/ci-cd-security.md](/Users/JoelN/Coding/argus/docs/guides/ci-cd-security.md)
- Plugin packaging: [docs/plugins/README.md](/Users/JoelN/Coding/argus/docs/plugins/README.md)

## License

MIT
