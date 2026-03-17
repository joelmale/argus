# Dependency Upgrade Plan

Revalidated on March 16, 2026.

## Current Status

Phase 0 is partially complete.

Completed stabilization work:
- The backend syntax error in the SMB probe was fixed.
- The frontend production build now passes.
- Frontend type errors that were blocking the build were fixed.
- `frontend/package-lock.json` and `frontend/next-env.d.ts` are now in the repo.
- Docker build performance was improved with [frontend/.dockerignore](/Users/JoelN/Coding/argus/frontend/.dockerignore).
- The dev startup flow and docs were aligned with the current Docker-based workflow.
- The Python dependency blocker was fixed by moving `pysnmp` from the nonexistent `6.1.2` release to `6.1.4`.

Still open before broad dependency upgrades:
- Frontend lint is still not a real non-interactive quality gate because there is no checked-in ESLint config. `npm run lint` still needs proper project setup.
- CI still points to `backend/tests/` even though there is no backend test suite.
- There is still no Alembic migration setup even though `alembic` is installed.
- Local runtime normalization is still incomplete. Docker and CI use Python 3.12 and Node 20, while local development on this machine is different.

## Remaining Findings

1. CI is still not fully reproducible.

   The frontend lint command is not yet a usable committed quality gate, and the backend CI job still expects tests that do not exist.

   References:
   - [frontend/package.json](/Users/JoelN/Coding/argus/frontend/package.json)
   - [.github/workflows/ci.yml](/Users/JoelN/Coding/argus/.github/workflows/ci.yml)

2. Database change management is still incomplete.

   `alembic` is installed, but the application still creates tables on startup and there is no Alembic config or migrations directory.

   Reference:
   - [backend/app/db/session.py](/Users/JoelN/Coding/argus/backend/app/db/session.py)

3. Runtime and tooling drift still increases upgrade risk.

   The repo targets Python 3.12 and Node 20 in Docker and CI. Local tooling should be normalized before major dependency moves.

   References:
   - [backend/Dockerfile](/Users/JoelN/Coding/argus/backend/Dockerfile)
   - [frontend/Dockerfile](/Users/JoelN/Coding/argus/frontend/Dockerfile)
   - [.github/workflows/ci.yml](/Users/JoelN/Coding/argus/.github/workflows/ci.yml)

## Updated Phase Plan

### Phase 0: Finish stabilization

Remaining work:
- Add a committed frontend ESLint config so `npm run lint` is non-interactive.
- Add a minimal backend smoke test and a minimal frontend smoke or CI-level validation step.
- Fix CI so it reflects the actual repo state.
- Pin or document local runtimes to match Docker and CI more closely.
- Decide whether `create_all()` startup schema creation stays temporary or is replaced now with Alembic bootstrap.

Exit criteria:
- Frontend lint, type-check, and build pass non-interactively
- Backend imports compile cleanly
- CI runs non-interactively
- At least minimal smoke coverage exists for backend and frontend

### Phase 1: Low-risk backend refresh

Upgrade these first:
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

Keep these as-is unless a specific issue appears:
- `passlib`
- `python-nmap`
- `netaddr`

### Phase 2: Backend infrastructure and protocol stack majors

Upgrade these in isolation:
- `websockets 12.0 -> 16.0`
- `python-multipart 0.0.9 -> 0.0.22`
- `httpx 0.27.0 -> 0.28.1`
- `redis 5.0.4 -> 7.3.0`
- `celery 5.3.6 -> 5.6.2`
- `pysnmp 6.1.4 -> 7.1.22`

Validation required:
- WebSocket events
- Auth form posts
- Celery worker startup
- Redis connectivity
- SNMP probing

### Phase 3: AI SDK upgrades behind an adapter boundary

Upgrade separately:
- `openai 1.35.0 -> 2.28.0`
- `anthropic 0.28.0 -> 0.85.0`

These should sit behind a thin compatibility layer first because the code currently uses chat and tool APIs directly.

### Phase 4: Frontend framework majors

Move these together:
- `next 14.2.3 -> 16.1.7`
- `react 18.3.1 -> 19.2.4`
- `react-dom 18.3.1 -> 19.2.4`
- `@types/react 18.3.28 -> 19.2.14`
- `@types/react-dom 18.3.7 -> 19.2.3`
- `eslint-config-next 14.2.3 -> 16.1.7`

Do `eslint` only in the range that the Next 16 move requires.

### Phase 5: Frontend ecosystem majors

Upgrade after the framework move:
- `tailwindcss 3.4.19 -> 4.2.1`
- `tailwind-merge 2.6.1 -> 3.5.0`
- `date-fns 3.6.0 -> 4.1.0`
- `zustand 4.5.7 -> 5.0.12`
- `recharts 2.15.4 -> 3.8.0`
- `next-themes 0.3.0 -> 0.4.6`
- `lucide-react 0.383.0 -> 0.577.0`

Treat Tailwind 4 as its own migration inside this phase because config and PostCSS setup usually change.

## Lower-Priority Or Already-Current Packages

These do not show the same immediate pressure:
- `@tanstack/react-query`
- `axios`
- `clsx`
- `class-variance-authority`
- `cytoscape`
- `cytoscape-fcose`
- `typescript`
- `postcss`
- `autoprefixer`
- `@types/cytoscape`
- `passlib`
- `python-nmap`
- `netaddr`

## Recommended Execution Order

1. Finish the remaining Phase 0 work
2. Upgrade low-risk backend packages
3. Upgrade backend infrastructure and protocol packages
4. Upgrade AI SDKs
5. Upgrade frontend framework packages
6. Upgrade frontend ecosystem packages
