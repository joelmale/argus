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

## Prerequisites

- Docker Desktop or Docker Engine with Compose
- A machine where Docker can use host networking for the backend and scanner services
- Permission to run containers with `NET_RAW` and `NET_ADMIN`

## Quick Start

For local development, use the setup script:

```bash
git clone https://github.com/joelmale/argus.git
cd argus
./scripts/setup.sh
```

This script now:
- copies `.env.example` to `.env` if needed
- builds the images with both `docker-compose.yml` and `docker-compose.dev.yml`
- starts Postgres and Redis first
- waits for both to become healthy
- starts the backend, scanner, and frontend in development mode

Equivalent manual command:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Notes:
- The first frontend startup may take a minute because the dev container installs dependencies into a named Docker volume.
- Later restarts reuse that volume and are faster unless `frontend/package-lock.json` changes.

Then open:
- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

## Common Commands

Start the full dev stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

Start in the background:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

Stop the stack:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml down
```

Rebuild only the frontend:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml build frontend
```

View logs:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml logs -f backend frontend scanner
```

## Current Dev Notes

- The backend and scanner use host networking, so Docker will warn that published ports on those services are discarded. That is expected with the current setup.
- The frontend runs in containerized dev mode with a persistent `node_modules` volume and reinstalls dependencies only when `frontend/package-lock.json` changes.
- Docker is currently the canonical way to run the app locally.

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
