# 🦅 Argus

> **Network asset discovery, inventory, and topology mapping for home labs.**
> Enterprise-grade visibility. Zero license cost. Runs on Docker.

[![CI](https://github.com/joelmale/argus/actions/workflows/ci.yml/badge.svg)](https://github.com/joelmale/argus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Features

- **Automatic discovery** — nmap active scanning + passive ARP listening
- **Asset inventory** — IP, MAC, hostname, OS, vendor, open ports, custom fields
- **Live topology map** — interactive force-directed graph (Cytoscape.js)
- **Change detection** — full audit trail of every asset change
- **Real-time updates** — WebSocket push for new devices and scan progress
- **REST API** — documented OpenAPI, every feature scriptable
- **SNMP support** — poll managed switches and routers *(Phase 2)*
- **Scheduled scans** — configurable interval via Celery Beat
- **Single Docker Compose** — one command to run everything

## Quick Start

```bash
git clone https://github.com/joelmale/argus.git
cd argus
./scripts/setup.sh
```

Then open:
- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

## Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14, React, TypeScript, Tailwind, Cytoscape.js |
| Backend | Python, FastAPI, SQLAlchemy async |
| Database | PostgreSQL 16 |
| Queue | Celery + Redis |
| Discovery | nmap, scapy, pysnmp |
| Runtime | Docker + Compose |

## Documentation

See [`docs/PLANNING.md`](docs/PLANNING.md) for the full architecture and roadmap.

## License

MIT
