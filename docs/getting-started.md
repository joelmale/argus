---
id: getting-started
title: Getting Started
sidebar_position: 3
---

# Getting Started

This guide covers the recommended local development workflow for Argus using Docker Compose.

## Prerequisites

- Docker Desktop for Mac or Docker Engine with Compose
- Node.js 20 for local script execution
- Python 3.12 only if you want host-local backend checks

For Docker Desktop for Mac, confirm the active Docker context is `desktop-linux`:

```bash
docker context ls
docker context use desktop-linux
```

:::info Docker Desktop for Mac
Most local development issues reported against Argus have been caused by Docker Desktop becoming unhealthy rather than by Compose configuration errors. If image inspection or build export steps start returning `500` errors, restart Docker Desktop first.
:::

## Initial Setup

Clone the repo and bootstrap the environment:

```bash
git clone https://github.com/joelmale/argus.git
cd argus
cp .env.example .env
npm run setup
```

The setup flow bootstraps the local environment, starts the required services, and runs the initial backend migration.

## Starting the Dev Stack

Foreground:

```bash
npm run dev
```

Background:

```bash
npm run dev:up
```

Stop:

```bash
npm run dev:down
```

View service logs:

```bash
npm run dev:logs
```

Check service state:

```bash
npm run dev:ps
```

Normal dev startup does not force a rebuild. Build explicitly when Dockerfiles or dependencies change:

```bash
npm run dev:build
```

Rebuild and restart:

```bash
npm run dev:rebuild
```

## Service Endpoints

Once the stack is running:

- frontend: `http://localhost:3000`
- backend API: `http://localhost:8000`
- OpenAPI docs: `http://localhost:8000/docs`

If there are no users yet, the login page will prompt you to create the initial admin account.

## Compose Files

`docker-compose.yml` is the production-oriented base stack. `docker-compose.dev.yml` adds source mounts, frontend dev mode, backend test tooling, and scanner host networking for local development.

## Why the Scanner Uses Host Networking

Argus needs accurate access to the local network for:

- active subnet scanning
- ARP-based discovery
- passive ARP observation

In development, the scanner is attached with `network_mode: host` to make this practical.

## First Recommended Steps

1. Log in to the UI.
2. Open `Settings`.
3. Review scanner targets and auto-detection behavior.
4. Configure SNMP or integration modules if needed.
5. Trigger a manual scan.

## Development Commands

### All-in-one checks

```bash
npm run verify
```

### Backend

```bash
npm run lint:backend
npm run test:backend
npm run test:backend:cov
npm run db:migrate
```

### Frontend

```bash
npm run lint:frontend
npm run type-check
npm run build
```

### Host-local backend checks

```bash
pip install -r backend/requirements-dev.txt
npm run lint:backend:local
npm run test:backend:local
```

## Notes About `.env`

`.env` is still used for bootstrap and runtime defaults, but several operational settings now have UI-backed persistence in the Settings page.

Examples:

- scanner defaults
- passive ARP and SNMP settings
- fingerprint AI settings
- internet lookup controls
- integration module settings

## Common Startup Issues

### Docker API returns `500` errors

Likely Docker Desktop instability.

Try:

```bash
docker version
docker ps
```

If those fail, restart Docker Desktop.

### Scanner finds the wrong subnet

Open `Settings` and review:

- explicit default targets
- auto-detect local subnet
- effective target resolution

### Frontend cannot talk to backend

Check:

- `http://localhost:8000/health`
- backend container health
- browser console for CORS or transport errors
- whether your browser is using same-origin `/api` routing or an outdated baked-in API URL

## Related Docs

- [Architecture](./architecture.md)
- [Scanner Guide](./guides/scanner.md)
- [Troubleshooting](./troubleshooting.md)
