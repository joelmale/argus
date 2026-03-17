# Dependency Upgrade Status

Last updated: March 17, 2026.

## Status

All planned dependency-upgrade phases are complete.

There are currently no active pending dependency-upgrade items in this plan.

## Completed Work

### Phase 0: Stabilization

Completed:
- Fixed the backend SMB probe syntax error.
- Fixed frontend type and build blockers.
- Added `frontend/package-lock.json` and `frontend/next-env.d.ts` to the repo baseline.
- Improved Docker build context handling with [frontend/.dockerignore](/Users/JoelN/Coding/argus/frontend/.dockerignore).
- Aligned startup scripts and documentation with the Docker-based workflow.
- Resolved the nonexistent `pysnmp==6.1.2` pin by moving to a valid release and then completing the full `pysnmp` upgrade in later phases.
- Made frontend lint, type-check, and build reproducible project checks.
- Added minimal backend tests and CI-safe validation.
- Pinned local runtime targets with `.nvmrc` and `.python-version`.

### Phase 1: Low-Risk Backend Refresh

Completed upgrades:
- `fastapi 0.111.0 -> 0.135.1`
- `uvicorn 0.29.0 -> 0.42.0`
- `sqlalchemy 2.0.30 -> 2.0.48`
- `asyncpg 0.29.0 -> 0.31.0`
- `alembic 1.13.1 -> 1.18.4`
- `python-jose 3.3.0 -> 3.5.0`
- `pydantic-settings 2.2.1 -> 2.13.1`
- `python-dotenv 1.0.1 -> 1.2.2`
- `aiofiles 23.2.1 -> 25.1.0`
- `structlog 24.1.0 -> 25.5.0`
- `mac-vendor-lookup 0.1.12 -> 0.1.15`
- `zeroconf 0.132.2 -> 0.148.0`
- `impacket 0.12.0 -> 0.13.0`
- `scapy 2.5.0 -> 2.7.0`
- `psycopg2-binary 2.9.9 -> 2.9.11`

Left intentionally unchanged:
- `passlib`
- `python-nmap`
- `netaddr`

### Phase 2: Backend Infrastructure and Protocol Stack Majors

Completed upgrades:
- `websockets 12.0 -> 16.0`
- `python-multipart 0.0.9 -> 0.0.22`
- `httpx 0.27.0 -> 0.28.1`
- `celery 5.3.6 -> 5.6.2`
- `pysnmp 6.1.4 -> 7.1.22`
- `redis 5.0.4 -> 6.4.0`

Compatibility note:
- `redis 7.x` was deferred because the currently resolved `celery[redis]` and `kombu` stack caps Redis below `6.5`.

### Phase 3: AI SDK Upgrades

Completed upgrades:
- `openai 1.35.0 -> 2.28.0`
- `anthropic 0.28.0 -> 0.85.0`

### Phase 4: Frontend Framework Majors

Completed upgrades:
- `next 14.2.3 -> 16.1.7`
- `react 18.3.1 -> 19.2.4`
- `react-dom 18.3.1 -> 19.2.4`
- `@types/react 18.3.28 -> 19.2.14`
- `@types/react-dom 18.3.7 -> 19.2.3`
- `eslint-config-next 14.2.3 -> 16.1.7`
- `eslint 8.x -> 9.39.4`

### Phase 5: Frontend Ecosystem Majors

Completed upgrades:
- `tailwindcss 3.4.19 -> 4.2.1`
- `tailwind-merge 2.6.1 -> 3.5.0`
- `date-fns 3.6.0 -> 4.1.0`
- `zustand 4.5.7 -> 5.0.12`
- `recharts 2.15.4 -> 3.8.0`
- `next-themes 0.3.0 -> 0.4.6`
- `lucide-react 0.383.0 -> 0.577.0`

## Post-Upgrade Follow-Up

Completed after the dependency phases:
- Alembic is bootstrapped and committed in [backend/alembic.ini](/Users/JoelN/Coding/argus/backend/alembic.ini) and [backend/alembic](/Users/JoelN/Coding/argus/backend/alembic).
- Startup `create_all()` schema creation has been removed from [backend/app/db/session.py](/Users/JoelN/Coding/argus/backend/app/db/session.py).

Deferred or periodic-review items:
- Revisit `redis 7.x` only when the Celery/Kombu compatibility range allows it cleanly.
- Recheck lower-priority libraries during future maintenance windows rather than treating them as active upgrade debt.

## No Active Pending Items

This document is now primarily a completion record. Future changes here should only be added when a new dependency-upgrade campaign starts or a currently deferred compatibility issue becomes actionable.
