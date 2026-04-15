---
id: improvement-roadmap
title: Performance, Architecture, and Functional Improvement Roadmap
sidebar_position: 15
---

# Performance, Architecture, and Functional Improvement Roadmap

This roadmap groups review recommendations into phases that can ship independently.
Each phase should produce focused commits with clear validation and rollback points.

## Goals

- Improve performance before inventory and scan history grow.
- Move domain behavior out of route handlers and into services.
- Fix edge cases around auth, scan lifecycle, and scanner resources.
- Add contracts and tests that make future changes safer.
- Keep every phase independently mergeable.

## Traceability

Use a short-lived branch for each phase or subphase.

Recommended branch names:

- `fix/phase-1-correctness`
- `perf/phase-2-query-shape`
- `perf/phase-3-asset-payloads`
- `refactor/phase-4-service-boundaries`
- `feature/phase-7-evidence-topology`
- `feature/phase-8-asset-identity`

Commit after each major behavior boundary, not after every small edit. Each commit
should describe one outcome and include its test or validation work.

Recommended commit format:

```text
<type>(<area>): <specific outcome>
```

Examples:

```text
fix(worker): dispose scanner task engines on early returns
perf(scans): filter and sort scan history in sql
refactor(assets): introduce summary and detail read services
test(e2e): cover logout and session expiry flows
```

## Validation

Run these checks before the first change in each phase:

```bash
npm run lint:frontend
npm run type-check
npm run test:backend:local
npm run build:frontend
```

For backend changes that affect SQL or scanner behavior, also run the relevant focused
backend tests before the full backend suite.

For frontend changes that affect browser behavior, add or run browser-level tests once
that test layer exists.

For performance changes, record before/after timings in the implementing pull request
for the affected routes or pages.

## Phase 1: Low-Effort Correctness Fixes ✓ Complete

Effort: Small

Shipped (2026-04-14):

- Scanner worker async engines now disposed on all early returns and exceptions
  (`_run_job_async`, `_enqueue_scheduled_scan`, `_run_scheduled_backups_async`,
  `_resume_paused_scans_async` all wrapped in `try/finally`).
- Admin-created user validation aligned with initial setup: username trimmed,
  minimum 3-character username enforced, minimum 10-character password enforced.
- Asset list query bounded (`skip >= 0`, `limit <= 500`) and ordered by
  `ip_address ASC`.
- "New Today" count switched from module-load rolling-24h window to calendar-day
  semantics.
- IPv6-aware IP sort in asset table; non-IPv4 values no longer sort incorrectly.
- Stale `createWsConnection` query-token helper removed from `api.ts`.

Purpose: fix concrete low-risk edge cases.

Scope:

- Ensure scanner worker async engines are disposed on every early return.
  - Wrap `_run_job_async`, `_enqueue_scheduled_scan`, `_run_scheduled_backups_async`,
    and `_resume_paused_scans_async` engine lifecycles in `try/finally` where needed.
- Align admin-created user validation with initial setup validation.
  - Trim username and email.
  - Enforce username length.
  - Enforce password length.
  - Preserve existing duplicate username/email behavior.
- Add deterministic asset-list ordering and query bounds.
  - Constrain `skip >= 0`.
  - Constrain `limit` to a safe maximum.
  - Add explicit ordering, preferably by `ip_address` or `last_seen`.
- Make "New Today" use calendar-day semantics instead of module-load rolling windows.
- Improve frontend IP sorting for IPv6 and non-IPv4 values.
- Remove or rewrite the unused WebSocket helper that sends tokens in the query string.
  - The active hook already uses first-message auth.
  - Avoid keeping a second, inconsistent auth pattern in the client API module.

Suggested commits:

```text
fix(worker): dispose scanner task engines on early returns
fix(auth): validate admin-created users consistently
fix(assets): bound and order asset list queries
fix(frontend): correct today counts and ip sorting
chore(websocket): remove stale query-token connection helper
```

Validation:

- `npm run test:backend:local`
- `npm run lint:frontend`
- `npm run type-check`
- `npm run build:frontend`
- Manual smoke:
  - create user as admin
  - list assets
  - sort IPv4 and IPv6-like addresses
  - open dashboard after midnight-sensitive date cases if practical

Rollback risk: Low. Changes are narrow and mostly corrective.

## Phase 2: Query Shape and Client-Side Performance ✓ Complete

Effort: Small to Medium

Shipped (2026-04-14, updated 2026-04-15):

- Scan-list filtering, sorting, and limiting moved into SQL (`CASE` expression for
  status priority; `LIMIT` applied in DB; `_scan_sort_key` Python helper removed).
- Alembic migration `20260414_0036_perf_indexes` added:
  - `pg_trgm` extension enabled (GIN trigram indexes accelerate ILIKE without
    changing query semantics; chosen over tsvector because trigrams handle partial IP
    address matching naturally).
  - GIN indexes on `assets.hostname`, `assets.vendor`, `assets.ip_address`.
  - B-tree indexes on `assets.status`, `assets.last_seen`, `asset_tags.asset_id`,
    `asset_tags.tag`, `asset_history.asset_id`, `probe_runs.asset_id`,
    `asset_evidence.asset_id`.
  - Composite index on `scan_jobs(parent_id, status, queue_position, created_at)`.
  - `max_length=200` constraint added to asset search parameter.
- API-key `last_used_at` writes throttled to 60-second intervals.
- Asset search input debounced 300 ms in the frontend.
- Asset table derived data (`views`, column options, filtered rows, sorted rows,
  visible IDs) memoized with `useMemo`.
- Dashboard widgets now share compact asset-summary queries and the asset stats
  endpoint instead of each issuing a full heavy asset-list fetch.
- Asset relationship collections now use ORM-level ordering for ports, tags, history,
  notes, evidence, probe runs, observations, fingerprint hypotheses, internet lookup
  results, and lifecycle records.
- Findings list endpoint paginated (`skip` / `limit`, default 200, max 1000).
- WebSocket handler switched from per-connection `redis.from_url()` to a shared
  module-level connection pool.
- Asset search kept `ILIKE` semantics but is backed by PostgreSQL trigram GIN indexes.
  This preserves partial IP, hostname, and vendor search behavior better than a
  tsvector-only search path.

Purpose: reduce unnecessary database, API, and browser work without changing the user
model.

Scope:

- Move scan-list filtering, sorting, and limiting into SQL.
  - Filter `parent_id IS NULL` in the query.
  - Use a SQL ordering equivalent to the current status priority.
  - Apply `LIMIT` in the database.
- Add database indexes for current access paths.
  - `assets.status`
  - `assets.hostname`
  - `assets.vendor`
  - `assets.last_seen`
  - `asset_tags.asset_id`
  - `asset_tags.tag`
  - `asset_history.asset_id`
  - `probe_runs.asset_id`
  - `asset_evidence.asset_id`
  - `scan_jobs(parent_id, status, queue_position, created_at)`
- Throttle API-key `last_used_at` writes.
  - Update only when unset or older than a configured interval.
  - Avoid committing during otherwise read-only API-key-authenticated requests.
- Debounce asset search input.
  - Keep local input responsive.
  - Send the API query only after a short quiet period.
- Memoize asset table derived data.
  - `views`
  - column filter options
  - filtered rows
  - sorted rows
  - visible asset IDs
- Avoid duplicate heavy asset-list fetches on dashboard widgets where possible.
  - Share compact asset-summary query results and use aggregate stats endpoints for
    dashboard counts.
- Move in-memory relationship sorting into SQL.
  - Add `ORDER BY` clauses or ORM `relationship(..., order_by=...)` for probe_runs,
    note_entries, evidence, observations, fingerprint_hypotheses, and
    internet_lookup_results so sorting is not repeated in the application layer for
    every asset returned.
- Add pagination to the findings list endpoint.
  - Add `skip` and `limit` parameters with a bounded default.
  - Consistent with the asset list bounds added in Phase 1.
- Pool the Redis connection used by the WebSocket handler.
  - Create a shared `aioredis` pool at app startup and pass it as app state.
  - Avoid creating a new `redis.from_url()` connection per WebSocket connection.
- Accelerate asset free-text search without changing current partial-match behavior.
  - Use PostgreSQL trigram GIN indexes for `hostname`, `vendor`, and `ip_address`.
  - Add a `max_length=200` constraint on the search query parameter.

Suggested commits:

```text
perf(scans): filter and sort scan history in sql
perf(db): add indexes for inventory and scan access paths
perf(auth): throttle api key last-used updates
perf(assets-ui): debounce search and memoize table derivations
perf(dashboard): avoid duplicate inventory fetches
perf(assets): move relationship sorting into sql order-by
perf(findings): add pagination to findings list endpoint
perf(websocket): pool redis connections at app startup
perf(assets): accelerate partial inventory search with gin indexes
```

Validation:

- Add backend tests for scan ordering and bounded asset-list query behavior.
- Add backend tests for bounded findings list behavior.
- Add a backend migration test or migration smoke for new indexes and `pg_trgm`.
- Compare route timings before and after the change.
- Verify dashboard and asset table still update after WebSocket invalidations.
- Verify asset search returns correct results for partial hostname, vendor, and IP matches.

Rollback risk: Low to Medium. SQL ordering and index migrations need careful review,
but behavior should remain equivalent.

## Phase 3: Asset API Payload Split ✓ Complete

Effort: Medium

Shipped (2026-04-15):

- Added explicit asset response models and serializers in `app.assets.serialization`.
- `GET /api/v1/assets/` now returns compact summaries by default.
- Optional list expansions are limited to `ports`, `tags`, `ai`, and `probe_runs`.
- `GET /api/v1/assets/{id}` remains the rich detail endpoint.
- Added `GET /api/v1/assets/stats` for dashboard aggregate counts and local
  calendar-day "new today" semantics.
- Frontend hooks now distinguish `AssetSummary`, `Asset`, and `AssetStats`.
- Asset list, dashboard widgets, SNMP workspace, WebSocket invalidation, and related
  components consume the compact summary shape without core asset `any` casts.
- Backend contract coverage now checks default summary payloads, optional expansions,
  and stats response shape.

Purpose: stop using the full asset detail payload for list/table/dashboard views.

Scope:

- Introduce explicit response models:
  - `AssetSummary`
  - `AssetDetail`
  - `AssetPortSummary`
  - `AssetAiSummary`
  - `AssetStats`
- Keep `GET /api/v1/assets/{id}` rich.
- Make `GET /api/v1/assets/` return summaries by default.
- Add optional expansion only where justified, for example:

```http
GET /api/v1/assets/?include=ports,tags,ai
```

- Move serialization out of the route module.
  - `AssetReadService`
  - `AssetSerializer` or Pydantic models
- Add a lightweight stats endpoint if dashboard still needs aggregate values:

```http
GET /api/v1/assets/stats
```

- Update frontend hooks and components to consume the summary shape.
- Keep detail pages using the detail endpoint.

Suggested commits:

```text
refactor(assets): add summary and detail response models
perf(assets): return compact summaries from list endpoint
refactor(frontend): consume asset summaries in list views
test(assets): cover summary and detail response contracts
```

Validation:

- Backend contract tests for summary and detail payloads.
- Frontend type-check confirms components no longer cast core asset fields to `any`.
- Compare payload size and route timing before and after the change.
- Manual smoke:
  - dashboard
  - asset list
  - asset detail
  - exports
  - tags and notes

Rollback risk: Medium. This phase changes API contracts, so it should be isolated and
well tested.

## Phase 4: Service Boundaries and Typed Client Contracts ✓ Complete

Effort: Medium

Purpose: make the codebase easier to evolve by reducing route-file responsibility and
frontend/backend type drift.

Shipped (2026-04-15):

- Added shared backend services for asset identity resolution, manual scan queue
  enqueueing, and topology graph reads.
- Route handlers for scan trigger, topology graph reads, and manual enrichment
  now delegate through smaller service helpers instead of carrying all of the
  orchestration inline.
- Asset identity resolution now normalizes MACs, avoids treating randomized
  locally administered MACs as durable primary keys, and records history entries
  for identity conflicts or randomized sightings.
- Backend scan trigger and asset enrichment endpoints are rate limited with the
  existing `slowapi` limiter.
- Backend logs now go through a JSON formatter at startup.
- Frontend asset detail and topology code removed avoidable `any` casts around
  `ai_analysis` and Cytoscape styling data.
- Added resolver coverage for randomized MAC handling and stable-MAC relocation.

Scope:

- Extract route logic into services:
  - `AssetReadService`
  - `AssetMutationService`
  - `AssetExportService`
  - `AssetEnrichmentService`
  - `AssetIdentityResolver`
  - `ScanQueueService`
  - `TopologyReadService`
- Keep FastAPI route handlers thin:
  - validate request
  - call service
  - return response model
- Centralize asset resolution in `AssetIdentityResolver`.
  - Keep the current schema and user-visible behavior in this phase.
  - Route scanner upsert, controller integrations, and passive log ingestion through
    one resolver instead of keeping separate IP-first and MAC-first paths.
  - Add conflict detection hooks for cases like same IP with a different stable MAC,
    same MAC on a new IP, or locally administered/randomized MAC sightings.
  - Record these as history or structured warnings first; defer the full
    sighting-first schema to Phase 8.
- Add response models to endpoints that currently return ad hoc dicts or ORM objects.
- Decide on API client strategy:
  - generate TypeScript from OpenAPI, or
  - keep manual client but type every response and request object explicitly.
- Remove frontend `any` casts around:
  - `ai_analysis`
  - `ports`
  - topology Cytoscape data where practical
  - asset detail mutation error paths
- Add structured JSON logging to the backend.
  - Use a JSON formatter (e.g. `python-json-logger`) configured at app startup.
  - Ensures all backend log output is machine-parseable for Loki, Grafana, or similar.
- Add per-user rate limiting to scan trigger and manual enrichment endpoints.
  - Apply the existing `slowapi` limiter (already used on the login route) to scan
    trigger, AI refresh, and SNMP refresh endpoints.
  - Prevents runaway scripts or a compromised API key from flooding the scanner or
    consuming external AI API quota.

Suggested commits:

```text
refactor(scans): move queue operations into service layer
refactor(assets): move exports and mutations out of route module
refactor(inventory): centralize asset identity resolution
refactor(topology): introduce topology read service
refactor(api): add response models for core endpoints
refactor(frontend): tighten api client and asset types
ops(logging): add structured json logging to backend
fix(api): rate-limit scan trigger and enrichment endpoints
```

Validation:

- Existing backend route tests continue to pass with service tests added around new
  service modules.
- Add resolver tests for current IP-first compatibility, MAC-first integration
  compatibility, and identity conflict detection.
- OpenAPI schema remains valid.
- Frontend type-check catches no `any` regressions for migrated areas.
- Verify structured log output is valid JSON for a sample of log levels.
- Verify rate-limited endpoints return HTTP 429 when the limit is exceeded.

Rollback risk: Medium. Behavior should not change, but refactors touch many files.
Use multiple commits and avoid bundling unrelated services into one commit.

## Phase 5A: Queued Refreshes and Scan Dispatch Locking

Status: Complete.

Implemented:

- Asset AI and SNMP refresh actions now enqueue jobs and return a job id.
- Scan queue writes and dispatch are protected with a PostgreSQL advisory lock.
- Queue progress and completion events now follow the same job lifecycle as scans.

## Phase 5B: Worker Topology and Session Lifecycle

Status: Complete.

Implemented:

- The worker now shares a lazy async session factory across long-running tasks.
- Worker shutdown disposes the shared database engine explicitly.
- Celery beat now runs in a separate scheduler service in both prod and dev compose files.

## Phase 5C: Export Jobs and WebSocket Reconnection

Status: Complete.

Implemented:

- CSV, Ansible, Terraform, inventory JSON, report JSON, and report HTML exports now queue background jobs and expose a download endpoint when complete.
- The asset inventory page polls scan job status until an export artifact is ready, then downloads it.
- WebSocket reconnect now uses exponential backoff and the sidebar shows a reconnecting state.
- Query polling backs off while the websocket is healthy and resumes when the connection drops.

## Phase 6: Topology and Metrics Scaling

Effort: Medium to Large

Purpose: reduce repeated full-graph and full-inventory work, surface topology
confidence clearly to the user, and give users the tools to correct and extend
topology data that automated scanning cannot fully resolve.

Purpose: reduce repeated full-graph and repeated metrics work.

Scope:

- Cache or materialize topology graph output.
  - Rebuild when assets, links, segments, or topology-relevant settings change.
  - Add ETag or last-updated metadata for client-side caching.
- Add separate topology sub-graph endpoints so clients can request less data:
  - full graph
  - graph summary (node count, edge count, segment list)
  - segment graph (nodes and edges within one segment)
  - selected asset neighborhood (node plus immediate parents and children)
- Emit a `topology:updated` WebSocket event after each scan completion and after
  any manual link mutation. The frontend subscribes and refetches automatically
  rather than polling or requiring a manual refresh.
- Cache metrics or compute them from lightweight aggregate queries.
  - Avoid a growing number of live count queries on every scrape.
- Consider separate topology endpoints:
  - full graph
  - graph summary
  - segment graph
  - selected asset neighborhood
- Optimize topology frontend lifecycle.
  - Avoid destroying and recreating Cytoscape for every filter change if incremental
    updates are practical.
  - Keep the current behavior until graph size makes this necessary.

Suggested commits:

```text
perf(topology): cache graph responses with invalidation metadata
perf(metrics): serve lightweight inventory counters
perf(topology-ui): avoid unnecessary graph recreation
```

Validation:

- Compare topology and metrics timings before and after the change.
- Verify graph updates after scans and manual link changes.
- Verify topology still renders after cache invalidation.
- Verify dashboard and metrics views still load.

Rollback risk: Medium to High.
- Caching: must be invalidated correctly or the UI shows stale topology.
- Suppression: ship behind a guard so a bug cannot silently hide all edges.
- Manual links: ship the API before the UI so the backend contract is tested
  independently.
- Cytoscape hot-swap: keep the destroy path reachable as a fallback if element
  diffing produces layout corruption on large graphs.

## Phase 7: Evidence-Based Topology Hierarchy ✓ Complete

Effort: Medium to Large

Shipped (2026-04-15):

- UniFi sync creates observed `wireless_ap_for` links from AP assets to client
  assets when controller client records include `ap_mac`.
- TP-Link Deco sync creates observed `wireless_ap_for` links from Deco node assets
  to wireless client assets when client records expose the serving AP name.
- Active scan persistence stores `avg_latency_ms` and `ttl_distance` on assets,
  and topology nodes serialize those values plus a latency-based `tier_hint`.
- SNMP probing collects Bridge MIB forwarding entries and topology ingestion
  creates observed `switch_port_for` links when learned MACs resolve to assets.
- Role inference now treats `access-point` and `switch` tags as high-confidence
  infrastructure evidence, with restrained Ubiquiti and TP-Link vendor scoring.
- Gateway fallback edges are now the last resort; Wi-Fi assets prefer a same-segment
  AP inference before falling back to the gateway.

Purpose: move topology graph construction away from broad gateway fallback edges and
toward observed or defensible parent-child relationships between infrastructure and
endpoints.

Problem statement:

- `backend/app/topology/graph_builder.py` currently has to connect many assets
  directly to the gateway because explicit `TopologyLink` records are missing for
  intermediate nodes such as access points, switches, and bridge ports.
- The topology should prefer verified controller and SNMP evidence first, use
  heuristics only when evidence is absent, and make gateway fallback the last resort.

Scope:

- Enrich controller link ingestion for UniFi and TP-Link.
  - Update `backend/app/modules/unifi.py` so `sync_unifi_module` creates explicit
    `TopologyLink` records when a `UnifiClientRecord` has `ap_mac`.
  - Resolve `ap_mac` to the existing access point `Asset`.
  - Reuse `_upsert_topology_link` from `backend/app/scanner/topology.py`.
  - Create `wireless_ap_for` links from AP asset to client asset with `observed=True`
    for API-verified controller data.
  - Add the equivalent behavior to the TP-Link integration if it exposes AP-to-client
    association data.
- Add latency and TTL evidence.
  - Add fields such as `avg_latency_ms` and `ttl_distance` to `Asset`, or equivalent
    observation fields if the sighting model from Phase 8 lands first.
  - Update the scanner pipeline to persist latency and TTL-distance values from active
    probes.
  - Treat sub-1.5 ms latency clustering as weak evidence that assets are on the same
    local switching fabric.
  - Use TTL carefully as hop-distance evidence. A Linux-like TTL of 64 often means no
    routed hop from the scanner, while 63 suggests one hop, but inference should be
    relative to common starting TTL families rather than an absolute device fact.
  - Include a node `tier_hint` in topology serialization, for example `< 2 ms` as
    `tier_1_local`.
- Add Layer 2 bridge table mapping through SNMP.
  - Extend `backend/app/scanner/topology.py` to query Bridge MIB
    `1.3.6.1.2.1.17.4.3`.
  - Map learned MAC addresses to switch `if_index` ports.
  - Create observed switch-to-endpoint links when a MAC can be mapped to a physical
    switch port.
  - Preserve enough detail to distinguish a directly attached wired endpoint from a
    downstream unmanaged switch or AP when evidence is ambiguous.
- Make role inference confidence-weighted.
  - Update `backend/app/topology/segments.py` so tags and vendor data contribute to
    topology role scoring.
  - Give a strong role score, up to `1.0`, to assets tagged `access-point` or
    `switch` when no stronger conflicting evidence exists.
  - Increase gateway or infrastructure candidate scores for Ubiquiti and TP-Link
    vendor data only when supported by tags, services, controller data, or observed
    link evidence.
- Restrict gateway fallback in `backend/app/topology/graph_builder.py`.
  - Modify `_build_inferred_gateway_edges` so it only creates gateway edges when no
    observed or higher-confidence inferred parent exists.
  - If an asset has a `wifi` tag but no observed link, look for an access point on the
    same `segment_id` and create an `inferred_wireless` edge with `observed=False`
    instead of defaulting to a gateway edge.
  - Keep heuristic links visibly distinct from observed links in API responses and
    graph metadata.

Suggested commits:

```text
feat(topology): ingest controller client ap links
feat(topology): persist latency and ttl distance evidence
feat(snmp): map bridge mib forwarding entries to switch ports
refactor(topology): weight role inference by tags and vendor evidence
refactor(topology): restrict gateway fallback edges
test(topology): cover observed ap and switch parent relationships
```

Validation:

- Unit tests for UniFi and TP-Link sync:
  - AP MAC resolves to an existing asset.
  - Client asset receives a `wireless_ap_for` parent link.
  - Controller-derived links use `observed=True`.
  - Missing AP assets do not create broken links.
- Unit tests for graph building:
  - Observed AP links suppress gateway fallback.
  - Observed switch-port links suppress gateway fallback.
  - Wi-Fi assets without observed links prefer same-segment AP inference before
    gateway fallback.
  - Heuristic links use `observed=False`.
- Unit tests for role inference:
  - `access-point` and `switch` tags produce strong infrastructure roles.
  - Ubiquiti and TP-Link vendor data improves infrastructure confidence without
    overriding stronger conflicting evidence.
- SNMP fixture tests for Bridge MIB parsing and MAC-to-`if_index` mapping.
- Manual smoke:
  - UniFi client appears under its AP in topology.
  - Wired endpoint appears under its switch when Bridge MIB evidence is present.
  - Assets without evidence still render through gateway fallback.

Implementation prompt:

```text
Act as a Senior Backend Engineer. Refactor the Argus topology system away from a
flat network map.

Goal: Improve build_topology_graph in backend/app/topology/graph_builder.py by
ensuring intermediate infrastructure, such as APs and switches, correctly claims
its children.

Tasks:

1. Update backend/app/modules/unifi.py. In sync_unifi_module, when a
   UnifiClientRecord has ap_mac, resolve that MAC to the access point Asset and
   reuse _upsert_topology_link from backend/app/scanner/topology.py to create a
   wireless_ap_for link between the AP Asset and the Client Asset.
2. Refine backend/app/topology/segments.py. Update infer_topology_role to give a
   1.0 role confidence score to assets tagged access-point or switch, and update
   score_gateway_candidate to incorporate access-point tags plus Ubiquiti or
   TP-Link vendor evidence.
3. Enhance backend/app/topology/graph_builder.py. Make _build_inferred_gateway_edges
   more restrictive. If an asset has a wifi tag but no observed parent link,
   attempt to find an access point role on the same segment_id and create an
   inferred_wireless edge instead of a gateway edge.
4. Add latency evidence. Add a latency field to Asset if no equivalent exists, and
   update topology node serialization to include a tier_hint, for example latency
   below 2 ms as Tier 1 / Local.

Constraints:

- Do not use TypeScript `any` types if frontend changes are required.
- Use SQLAlchemy AsyncSession for all database interactions.
- Use observed=True for API-verified data and observed=False for heuristic data.
```

Rollback risk: Medium to High. The graph should remain renderable through gateway
fallback, but incorrect link confidence can materially change the user's mental model
of the network. Ship controller-derived observed links before heuristic graph changes.

## Phase 8: Sighting-First Inventory Model Evolution

Effort: Large

Purpose: return quick discovery results while separating temporary network sightings
from durable assets.

Scope:

- Rework inventory around three concepts:
  - `IdentityObservation`: a raw fact from scan, ARP, DHCP, mDNS, SNMP, controller
    APIs, logs, or manual input.
  - `Endpoint`: a currently observed network presence such as IP, MAC, hostname,
    source, network scope, and time window.
  - `Asset`: the durable device, VM, service host, router, printer, phone, or other
    thing the user cares about.
- Keep discovery fast by creating provisional records immediately.
  - New scan results should appear in the UI without waiting for strong correlation.
  - Add `identity_state` values such as `provisional`, `confirmed`, `conflicted`,
    `retired`, and `ignored`.
  - Add `identity_confidence` and `primary_signal` so users can see why a record
    exists and how certain the system is.
- Add sighting and assignment tables.
  - `asset_identity_observations` for raw observed IP, MAC, hostname, source,
    controller ID, DHCP client ID, SNMP identity, TLS certificate fingerprint, and
    confidence details.
  - `asset_interfaces` for stable interfaces and non-randomized MAC addresses.
  - `asset_address_assignments` for IP addresses over time, scoped by subnet, VLAN,
    site, or integration source where available.
  - Support multiple IPs per asset, reused IPs over time, and overlapping private
    address space across network scopes.
- Replace single-field primacy with confidence-based reconciliation.
  - Strong signals: controller device ID, serial number, SNMP serial, stable TLS
    certificate fingerprint, or manually confirmed identity.
  - Medium signals: non-randomized MAC, DHCP client ID, stable hostname with matching
    vendor or service profile.
  - Weak signals: IP address alone, hostname alone, one passive log line, or a locally
    administered/randomized MAC by itself.
  - Use IP as a presence/address signal, not a durable identity signal.
- Handle randomized MACs without flooding inventory.
  - Detect locally administered MAC addresses and treat them as weak identity signals.
  - Store one-time randomized sightings as observations or provisional endpoints,
    not automatically as confirmed durable assets.
  - Add retention for low-confidence provisional records and unresolved observations.
  - Add per-scan, per-source, or per-subnet caps for weak provisional records.
  - Avoid "new asset" notifications for one-time low-confidence randomized sightings.
- Add explicit reconciliation outcomes.
  - Promote provisional records when enough evidence accumulates.
  - Merge duplicate provisional records when confidence is high and no strong conflict
    exists.
  - Split records when a strong signal proves that an IP or weak MAC was reused.
  - Mark noisy or unwanted records as ignored so future scans do not recreate them.
  - Record `identity_conflicts` instead of silently merging when strong signals
    disagree.
- Migrate from destructive fingerprint refresh to separate snapshot and history.
  - Keep current evidence snapshot for the asset detail summary.
  - Preserve probe-run history with retention policies.
  - Add `scan_id` or `job_id` references to evidence/probe records.
- Add migration strategy.
  - Backfill observations, interfaces, and address assignments from current
    `Asset.ip_address`, `Asset.mac_address`, hostname, evidence, and passive
    observations.
  - Preserve existing asset IDs where possible.
  - Keep `Asset.ip_address` and `Asset.mac_address` temporarily as denormalized
    current/display fields until API consumers are migrated.
- Update resolver and upsert behavior.
  - Route scanner results, passive logs, and integrations through the shared
    `AssetIdentityResolver` introduced in Phase 4.
  - Score observations by signal strength and source confidence.
  - Use IP-only matches as provisional unless corroborated by stronger signals.
  - Avoid merging unrelated devices solely because an IP was reused.
  - Avoid creating durable assets solely because a randomized MAC appeared once.
- Update API and UI contracts.
  - Show provisional, confirmed, conflicted, ignored, and retired states in asset
    summary/detail responses.
  - Expose identity evidence, current address assignments, and conflicts on asset
    detail.
  - Add review actions for promote, merge, split, ignore, and retire.

Suggested commits:

```text
feat(inventory): add sighting and address assignment models
feat(inventory): add provisional asset lifecycle states
refactor(upsert): reconcile assets with identity resolver scores
feat(inventory): handle randomized mac sightings as weak signals
feat(inventory): add identity conflict and review actions
feat(fingerprints): separate current evidence snapshot from probe history
migration(inventory): backfill observations and assignments from existing assets
test(inventory): cover dhcp churn randomized macs and multi-interface assets
```

Validation:

- Migration test with existing inventory data.
- Resolver tests for:
  - quick provisional creation from IP-only discovery
  - promotion when stronger evidence appears later
  - same stable MAC on a new IP
  - new stable MAC reusing an old IP
  - locally administered/randomized MAC churn
  - hostname and service-profile corroboration
  - overlapping private IPs in different network scopes
- Upsert tests for:
  - same MAC new IP
  - new MAC reused IP
  - multi-interface device
  - passive observation before active scan
  - scan with no MAC address
- Flood-control tests for weak one-time sightings, retention, and per-scan caps.
- Notification tests proving low-confidence randomized sightings do not trigger
  "new asset" alerts.
- Manual smoke on existing asset detail and topology pages.
- Manual smoke for promote, merge, split, ignore, and retire review flows.

Rollback risk: High. This is a model change and should be implemented only after the
smaller API and service-boundary phases make the code easier to modify.

## Phase 9: Release Pipeline and Browser Test Coverage

Effort: Medium to Large

Purpose: improve deployment confidence and catch frontend/session regressions before
release images publish.

Scope:

- Build release images once and scan the exact artifact that will be pushed.
  - Avoid the current build-for-scan, build-for-push duplication.
  - Preserve SBOM, provenance, signing, and SARIF upload.
- Add frontend/browser CI coverage.
  - Auth/login setup flow.
  - Logout returns to `/login`.
  - Session expiry redirects and clears invalid token.
  - Asset search and sort.
  - Scan queue controls.
  - Version badge shows build metadata.
- Add API contract checks where feasible.
  - OpenAPI schema generation.
  - TypeScript client generation or schema drift detection.
- Add phase-specific CI jobs only when affected files change, matching the existing
  development workflow.

Suggested commits:

```text
ci(images): scan the same image digest that is pushed
test(e2e): cover auth setup logout and session expiry
test(e2e): cover asset table and scan queue workflows
ci(contract): validate openapi and frontend api types
```

Validation:

- Pull request checks pass.
- Release image workflow publishes backend, scanner, and frontend images.
- Trivy scans still upload SARIF artifacts.
- E2E tests pass locally and in CI.

Rollback risk: Medium. CI changes affect release flow, so keep them separate from
runtime application changes.

## Phase 10: Hardening and UX Polish

Effort: Medium

Purpose: harden security and operational configuration, and improve accessibility,
empty-state handling, and first-use experience without touching core data paths.

Scope:

- Add security headers middleware to the FastAPI app.
  - Set `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a baseline
    Content Security Policy on every response.
  - Use a small custom Starlette middleware; no additional dependencies required.
- Add `depends_on: redis: condition: service_healthy` to the backend and scanner
  services in Docker Compose.
  - Prevents startup race conditions where Celery or the WebSocket handler fails
    silently because Redis is not yet accepting connections.
- Validate nmap arguments in custom scan profiles before enqueueing.
  - Reject arguments containing shell metacharacters (`$`, `;`, `|`, backticks, etc.)
    or use an allowlist of safe nmap flags.
  - Prevents command injection through the custom scan profile path.
- Configure the SQLAlchemy async engine connection pool explicitly.
  - Set `pool_size`, `max_overflow`, `pool_recycle`, and `pool_pre_ping=True` as
    environment-variable-tunable settings.
  - Prevents connection pool exhaustion under concurrent scan load and eliminates
    stale-connection failures after database restarts.
- Add pagination UI to the asset table.
  - Wire the existing `skip`/`limit` backend parameters to pagination controls in the
    frontend.
  - Move sort column and direction into the server-side query so the browser is not
    sorting the full dataset.
- Replace `window.confirm` dialogs with accessible modal dialogs.
  - Use the existing shadcn/ui `AlertDialog` component for bulk delete and other
    destructive confirmations.
  - `window.confirm` is not keyboard-trappable, cannot be styled, and is blocked in
    some embedded contexts.
- Add skeleton loaders to dashboard widgets.
  - Use Tailwind `animate-pulse` shapes matching the final layout for StatsGrid,
    DeviceTypeChart, and OsCompositionWidget.
  - Eliminates layout shift and makes loading state explicit rather than blank.
- Add empty states for pages with no data.
  - Assets page, findings page, topology view, and dashboard should each show a
    contextual message and a primary action (e.g. "Run a scan to discover your network")
    when the inventory is empty.
  - Reduces confusion for first-time users after initial setup.
- Add `aria-label` attributes to all icon-only interactive elements.
  - Covers the Enrich button, scan action icon buttons, and any other controls that
    rely on a tooltip or `title` attribute alone.
- Add a global React error boundary at the app shell level.
  - Catch component-level errors and render a fallback UI instead of a blank page.
  - The fallback should allow navigation to other pages without a full reload.
- Add stale-data indicators to polling components.
  - Show a "Last updated N seconds ago" timestamp with a manual refresh button on
    asset list and dashboard widgets.
  - Suppress the 60-second polling interval when the WebSocket is connected (relies
    on the reconnection work in Phase 5).

Suggested commits:

```text
fix(security): add security headers middleware to fastapi app
ops(compose): add redis health dependency for backend and scanner
fix(scanner): validate nmap arguments before scan dispatch
perf(db): configure sqlalchemy connection pool via env vars
feat(assets-ui): add server-side pagination to asset table
fix(ui): replace window.confirm with accessible alert dialogs
feat(ui): add skeleton loaders to dashboard widgets
feat(ui): add empty states to assets findings topology and dashboard
fix(accessibility): add aria-labels to icon-only buttons
feat(frontend): add global react error boundary
feat(ui): show last-updated indicator on polling components
```

Validation:

- Verify security headers are present on all API responses with a curl or browser
  network tab check.
- Verify `docker compose up` starts cleanly without backend/scanner errors when Redis
  takes a few extra seconds.
- Attempt a custom scan profile with shell metacharacters in the nmap args field;
  confirm the job is rejected before enqueueing.
- Confirm pool settings take effect under concurrent load (no idle connection errors
  in backend logs).
- Manual smoke:
  - asset table pagination and server-side sort
  - bulk delete confirmation uses modal, not browser confirm
  - dashboard skeleton appears during initial load
  - fresh install (empty database) shows empty states on all affected pages
  - screen reader or axe audit confirms no icon-only button violations
  - throw a deliberate error in a component; confirm error boundary catches it
  - disconnect from the network; confirm stale indicator appears in asset table

Rollback risk: Low to Medium. Most changes are additive. The pagination UI change
alters how the asset table loads data and should be validated against the existing
table filter and sort behaviors.

## Recommended Implementation Order

Implement in this order unless production pressure changes the priority:

1. ~~Phase 1: correctness fixes.~~ ✓ Done (2026-04-14)
2. ~~Phase 2: query shape and client-side performance.~~ ✓ Done (2026-04-14, completed 2026-04-15).
3. ~~Phase 3: asset API payload split.~~ ✓ Done (2026-04-15).
4. Phase 9 image build portion: scan the pushed artifact.
5. Phase 4: service boundaries and typed contracts.
6. Phase 5: async workflows and queue hardening.
7. Phase 6: topology and metrics scaling.
8. Phase 7: evidence-based topology hierarchy.
9. Phase 10: hardening and UX polish.
10. Phase 9 E2E coverage expansion.
11. Phase 8: sighting-first inventory model evolution.

Reasoning:

- Phases 1 and 2 reduce immediate risk with low complexity.
- Phase 3 removes the biggest performance bottleneck before larger refactors.
- The release workflow improvement is independent and can land early.
- Service extraction is safer after compact response contracts exist, and the shared
  identity resolver in Phase 4 keeps later identity changes from touching every
  scanner and integration path at once.
- Queue and worker changes should happen after service boundaries clarify ownership.
- Phase 7 topology hierarchy work should follow the cheaper topology serving work in
  Phase 6 so graph correctness changes can be validated without fighting full-graph
  performance bottlenecks.
- Phase 10 security and configuration items (headers, nmap validation, pool config)
  are low-blast-radius and can land in parallel with Phase 6; the UX items follow
  naturally once the payload and async work from Phases 3 and 5 are stable.
- The sighting-first inventory redesign should wait until the surrounding code is
  cleaner and contract coverage is stronger.

## Done Criteria

The roadmap is complete when:

- ✓ Asset list and scan list scale without loading unnecessary rows or relationships.
- ✓ Findings list is paginated and bounded.
- ✓ Relationship collections are sorted in SQL, not in the application layer.
- ✓ Dashboard views avoid duplicate heavy fetches.
- Topology views avoid duplicate heavy fetches.
- Topology graph uses observed controller and SNMP links before gateway fallback.
- Gateway fallback is reserved for assets with no observed or higher-confidence
  inferred parent.
- AP and switch role inference uses tags, vendor data, controller evidence, and
  observed links rather than gateway proximity alone.
- ✓ Asset search uses GIN-indexed trigram ILIKE instead of unbounded unindexed queries.
- Long-running manual refresh actions and exports are queued and observable.
- Scan dispatch is concurrency-safe.
- ✓ Worker resources are disposed consistently.
- ✓ Auth and user-management validation is consistent.
- Backend log output is structured JSON.
- Scan trigger and enrichment endpoints are rate-limited.
- Security headers are present on all API responses.
- Nmap arguments are validated before scan dispatch.
- ✓ Redis connection pool shared across WebSocket connections.
- SQLAlchemy connection pool is explicitly configured for concurrent load.
- WebSocket client reconnects automatically after connection loss.
- Asset table pagination is server-side.
- All destructive confirmations use accessible modal dialogs.
- Empty states and skeleton loaders are present throughout the UI.
- All icon-only interactive elements have accessible labels.
- A global error boundary prevents full-page crashes from component errors.
- Frontend core flows have browser-level coverage.
- Release images are scanned as the same artifact that gets pushed.
- Discovery returns quick provisional records before identity is fully confirmed.
- Asset tracking separates raw observations, current endpoints, and durable assets.
- Asset identity can represent IP churn, overlapping private IPs, randomized MACs,
  and multi-interface devices.
- Weak one-time randomized MAC sightings do not flood durable inventory or trigger
  noisy new-asset notifications.
- Identity conflicts are recorded and reviewable instead of silently merged.
- Users can promote, merge, split, ignore, retire, and review identity confidence.
- Evidence/probe history is retained separately from current fingerprint state.
