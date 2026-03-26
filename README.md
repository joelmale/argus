# Argus

Network discovery, inventory, fingerprinting, topology mapping, and homelab operations visibility.

[![PR Checks](https://github.com/joelmale/argus/actions/workflows/pr-checks.yml/badge.svg)](https://github.com/joelmale/argus/actions/workflows/pr-checks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Argus is a self-hosted network inventory and operations platform for homelabs and small private environments. It scans and enriches your network, tracks asset changes over time, exposes a REST API and live event stream, and provides a dashboard for assets, scans, findings, topology, backups, and settings.

Docs site:

- https://joelmale.github.io/argus/

## Core Capabilities

- Active discovery with `nmap`, plus passive observations and imported network evidence
- Asset inventory with ports, findings, notes, tags, history, AI analysis, and supporting evidence
- Evidence-driven fingerprinting using MAC OUI, service banners, SNMP, HTTP/TLS/SSH hints, and optional AI synthesis
- Topology views, live scan progress, findings, config backups, and exports
- Homelab-focused modules such as TP-Link Deco support and local AI integration

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

## Common Commands

Most local workflows start here:

```bash
npm run dev
npm run dev:up
npm run dev:down
npm run dev:logs
npm run verify
```

## Documentation

Use the docs site for setup, architecture, operations, and development workflow details:

- Docs home: https://joelmale.github.io/argus/
- Getting started: https://joelmale.github.io/argus/getting-started
- Architecture: https://joelmale.github.io/argus/architecture
- Scanner guide: https://joelmale.github.io/argus/guides/scanner-guide
- Scan profiles: https://joelmale.github.io/argus/guides/scan-profiles
- Settings reference: https://joelmale.github.io/argus/guides/settings-reference
- Backend API: https://joelmale.github.io/argus/guides/backend-api-guide
- Frontend dashboard: https://joelmale.github.io/argus/guides/frontend-dashboard-guide
- CI/CD and security: https://joelmale.github.io/argus/guides/ci-cd-security
- Development workflow: https://joelmale.github.io/argus/guides/development-workflow
- Troubleshooting: https://joelmale.github.io/argus/troubleshooting

The markdown source for the docs lives in [`docs/`](docs/), and the Docusaurus site lives in [`website/`](website/).

## Screenshots and Images

Put screenshots and docs-site images here:

- [`website/static/img/screenshots/`](website/static/img/screenshots/)

Why this location:

- Docusaurus serves everything under `website/static/` directly
- screenshots can be referenced in docs with `/img/screenshots/<file>`
- the same files can be linked from the README using the GitHub raw/blob URLs if needed

Example docs image reference:

```md
![Asset Inventory](/img/screenshots/assets-overview.png)
```

## Configuration

Development uses `.env`. The production compose stack reads [.env.production](.env.production) as a template and expects deployment-specific values to be overridden in your deployment platform.

## License

MIT
