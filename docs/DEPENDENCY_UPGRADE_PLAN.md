# Dependency Upgrade Plan

Reviewed on March 16, 2026.

## Findings

1. The backend is not at a clean baseline: there is a syntax error in the SMB probe that prevents full module compilation now, before any dependency work.

   Reference: [backend/app/scanner/probes/smb.py](/Users/JoelN/Coding/argus/backend/app/scanner/probes/smb.py)

2. The frontend does not type-check cleanly. The shared type layer is already out of sync with consumers: missing `DeviceClass`, missing WebSocket event variants, and invalid casts and branches in store and socket handling.

   References:
   - [frontend/src/types/index.ts](/Users/JoelN/Coding/argus/frontend/src/types/index.ts)
   - [frontend/src/components/ui/Badge.tsx](/Users/JoelN/Coding/argus/frontend/src/components/ui/Badge.tsx)
   - [frontend/src/hooks/useWebSocket.ts](/Users/JoelN/Coding/argus/frontend/src/hooks/useWebSocket.ts)
   - [frontend/src/store/index.ts](/Users/JoelN/Coding/argus/frontend/src/store/index.ts)
   - [frontend/src/components/assets/AssetTable.tsx](/Users/JoelN/Coding/argus/frontend/src/components/assets/AssetTable.tsx)

3. CI is not reproducible in its current form. The frontend lint command is interactive because there is no checked-in ESLint config, and the backend CI job points at `backend/tests/` even though there is no test suite present.

   References:
   - [frontend/package.json](/Users/JoelN/Coding/argus/frontend/package.json)
   - [.github/workflows/ci.yml](/Users/JoelN/Coding/argus/.github/workflows/ci.yml)

4. Database change management is incomplete. `alembic` is installed, but the app still creates tables on startup and there is no Alembic config or migrations directory. That makes SQLAlchemy/Alembic upgrades riskier than they need to be.

   Reference: [backend/app/db/session.py](/Users/JoelN/Coding/argus/backend/app/db/session.py)

5. Runtime and tooling drift will complicate upgrades unless it is normalized first. The repo targets Python 3.12 and Node 20 in Docker and CI, while the local machine is currently on Python 3.10.13 and Node 25.8.1.

   References:
   - [backend/Dockerfile](/Users/JoelN/Coding/argus/backend/Dockerfile)
   - [frontend/Dockerfile](/Users/JoelN/Coding/argus/frontend/Dockerfile)
   - [.github/workflows/ci.yml](/Users/JoelN/Coding/argus/.github/workflows/ci.yml)

## Phased Plan

### Phase 0: Stabilize the baseline

Fix the syntax error, make `npm run lint` non-interactive, fix the current TypeScript errors, add a minimal backend smoke test and minimal frontend smoke or type gate, commit the frontend lockfile, and pin local runtimes to the same Python and Node versions used in CI and Docker.

Exit criteria:
- Frontend lint, type-check, and build pass
- Backend imports compile cleanly
- CI runs non-interactively

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

Keep `passlib`, `python-nmap`, and `netaddr` as-is unless a specific issue appears.

### Phase 2: Backend infrastructure and protocol stack majors

Upgrade these in isolation:
- `websockets 12.0 -> 16.0`
- `python-multipart 0.0.9 -> 0.0.22`
- `httpx 0.27.0 -> 0.28.1`
- `redis 5.0.4 -> 7.3.0`
- `celery 5.3.6 -> 5.6.2`
- `pysnmp 6.1.2 -> 7.1.22`

Validation required:
- WebSocket events
- Auth form posts
- Celery worker startup
- Redis connectivity
- SNMP probing

### Phase 3: AI SDK upgrades behind an adapter boundary

Upgrade these separately:
- `openai 1.35.0 -> 2.28.0`
- `anthropic 0.28.0 -> 0.85.0`

These should be wrapped behind a small compatibility layer before upgrading because the code directly uses chat and tool APIs.

### Phase 4: Frontend framework majors

Move these together:
- `next 14.2.3 -> 16.1.7`
- `react 18.3.1 -> 19.2.4`
- `react-dom 18.3.1 -> 19.2.4`
- `@types/react 18.3.28 -> 19.2.14`
- `@types/react-dom 18.3.7 -> 19.2.3`
- `eslint-config-next 14.2.3 -> 16.1.7`

Do `eslint` only in the range required by Next 16 during that move.

### Phase 5: Frontend ecosystem majors

Upgrade these after the framework move:
- `tailwindcss 3.4.19 -> 4.2.1`
- `tailwind-merge 2.6.1 -> 3.5.0`
- `date-fns 3.6.0 -> 4.1.0`
- `zustand 4.5.7 -> 5.0.12`
- `recharts 2.15.4 -> 3.8.0`
- `next-themes 0.3.0 -> 0.4.6`
- `lucide-react 0.383.0 -> 0.577.0`

Treat Tailwind 4 as its own migration within this phase because config and PostCSS setup usually change.

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

1. Complete Phase 0
2. Upgrade low-risk backend packages
3. Upgrade backend infrastructure and protocol packages
4. Upgrade AI SDKs
5. Upgrade frontend framework packages
6. Upgrade frontend ecosystem packages
