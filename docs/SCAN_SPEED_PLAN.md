# Scan Speed And UX Plan

This document captures the phased plan for making Argus scans feel faster, return useful results earlier, and provide clearer operator feedback during large network scans.

## Implementation Checklist

- [x] Phase 1: Scan Modes
  - Current status: completed
  - Completed:
    - added `quick`, `balanced`, and `deep_enrichment` backend scan modes
    - mapped legacy `polite` and `aggressive` values into the new model for compatibility
    - exposed the new modes in the scans UI and settings default-profile selector
- [x] Phase 2: Per-Stage Live Persistence
  - Current status: completed
  - Completed:
    - discovery results now persist before the port-scan/investigation work completes
    - investigated hosts now persist as they finish
    - asset events now carry stage-aware updates during the scan
    - final persistence is reduced to offline reconciliation instead of a single end-of-job flush
- [ ] Phase 3: Results-So-Far UX
  - Current status: partial
  - Completed:
    - live stage/progress updates
    - current host display
    - discovered-host and investigated-host counters
  - Gaps:
    - no dedicated counters yet for port-scanned, fingerprinted, deep-probed, assets created, and assets updated
    - no direct shortcut from the active scan to assets discovered so far
- [ ] Phase 4: Performance Settings
  - Current status: partial
  - Completed:
    - database-backed `default_profile`
    - database-backed `concurrent_hosts`
  - Gaps:
    - chunk size not configurable
    - top ports count not configurable
    - deep-probe timeout not configurable
    - AI after-scan toggle not configurable
- [ ] Phase 5: Chunked Parent/Child Scan Jobs
  - Current status: not started
  - Gaps:
    - no parent/child scan-job model
    - no chunk orchestration for large scans
    - queueing still operates at the single-job level
- [ ] Phase 6: Deep Enrichment Follow-Up Workflow
  - Current status: not started
  - Gaps:
    - no dedicated follow-up enrichment action for discovered hosts or selected assets
    - no post-inventory enrichment workflow in the scans or assets UI

## Goals

- Reduce time to first visible result.
- Persist and display useful partial results while scans are still running.
- Separate fast inventory collection from slower deep enrichment.
- Improve operator control and visibility for large or long-running scans.
- Make performance tuning configurable instead of code-driven.

## Guiding Principles

- Favor early, incremental value over monolithic scan completion.
- Use concurrency carefully; avoid creating duplicate or conflicting scans.
- Optimize for perceived speed as well as total wall-clock time.
- Keep deep enrichment optional and staged behind faster discovery passes.

## Phase 1: Scan Modes

Commit point: `Add quick and deep scan mode framework`

### Scope

- Add explicit scan modes:
  - `quick`
  - `balanced`
  - `deep_enrichment`
- Define scan mode behavior in a single backend location.
- Make `quick` scans optimized for first-pass inventory:
  - host discovery
  - limited top-port scan
  - minimal fingerprinting
  - AI disabled by default
- Make `deep_enrichment` optimized for follow-up investigation of known hosts:
  - deeper probes
  - more service inspection
  - optional AI analysis

### Likely Files

- `backend/app/scanner/models.py`
- `backend/app/scanner/config.py`
- `backend/app/api/routes/scans.py`
- `frontend/src/app/scans/page.tsx`

### Outcome

Users can choose a fast first-pass scan instead of always paying for the full deep-investigation cost.

Checklist:

- [x] Add `quick`, `balanced`, and `deep_enrichment` modes in one backend definition
- [x] Make `quick` skip AI by default
- [x] Make `quick` limit the initial port scan depth
- [x] Make `quick` avoid the heavier deep-probe stage
- [x] Make `deep_enrichment` run the heavier scan/probe path
- [x] Expose the new modes in the scans UI
- [x] Expose the new default profile choices in settings

## Phase 2: Per-Stage Live Persistence

Commit point: `Persist partial scan results by stage`

### Scope

- Persist discovery results immediately.
- Persist port results as each host completes.
- Persist fingerprinting and probe results incrementally.
- Add stage information to scan and asset updates.
- Stop waiting for full job completion before assets appear or update.

### Likely Files

- `backend/app/scanner/pipeline.py`
- `backend/app/db/upsert.py`
- `backend/app/db/models.py`

### Outcome

Assets begin appearing and improving during the scan instead of only after final completion.

Checklist:

- [x] Persist discovery-only results immediately
- [x] Persist investigated hosts as they complete
- [x] Emit stage-aware asset updates while the scan is still active
- [x] Stop waiting for the final scan completion before assets appear

## Phase 3: Results-So-Far UX

Commit point: `Add progressive scan counters and summaries`

### Scope

- Add live counters on the scans page for:
  - discovered hosts
  - hosts port scanned
  - hosts fingerprinted
  - hosts deep probed
  - assets created
  - assets updated
- Improve per-scan progress summaries.
- Add clearer stage transitions to reduce “is it stuck?” confusion.
- Optionally add a shortcut to view assets discovered so far from the active scan.

### Likely Files

- `frontend/src/components/scans/ScanHistory.tsx`
- `frontend/src/app/scans/page.tsx`
- `frontend/src/types/index.ts`

### Outcome

Scans feel active and understandable while they are in progress.

Checklist:

- [ ] Show discovered-host count
- [ ] Show port-scanned count
- [ ] Show fingerprinted count
- [ ] Show deep-probed count
- [ ] Show assets created count
- [ ] Show assets updated count
- [ ] Improve stage labeling to reduce “is it stuck?” confusion
- [ ] Add a shortcut to view assets discovered from the active scan

## Phase 4: Performance Settings

Commit point: `Add advanced scan performance settings`

### Scope

- Add configurable settings for:
  - host concurrency
  - chunk size
  - top ports count
  - deep-probe timeout
  - AI after-scan toggle
- Add safe bounds and help text.
- Persist settings in the database.
- Keep reasonable defaults for home-lab use.

### Likely Files

- `backend/app/scanner/config.py`
- `backend/app/api/routes/system.py`
- `frontend/src/app/settings/page.tsx`

### Outcome

Operators can tune scan speed and scan depth for their own network without code changes.

Checklist:

- [ ] Add host concurrency setting
- [ ] Add chunk size setting
- [ ] Add top ports count setting
- [ ] Add deep-probe timeout setting
- [ ] Add AI after-scan toggle
- [ ] Add bounds/help text for each setting

## Phase 5: Chunked Parent/Child Scan Jobs

Commit point: `Split large scans into chunked child jobs`

### Scope

- Introduce parent scan jobs for large targets.
- Split large targets into child chunks, likely `/24` blocks or configurable host batches.
- Run child chunks in controlled sequence or limited parallelism.
- Aggregate child progress back into the parent scan job.
- Keep queue management at the parent-job level.

### Likely Files

- `backend/app/db/models.py`
- `backend/app/api/routes/scans.py`
- `backend/app/workers/tasks.py`

### Outcome

Large scans start yielding results from early chunks quickly, and orchestration becomes more predictable.

Checklist:

- [ ] Add parent scan jobs
- [ ] Add child chunk jobs
- [ ] Split large targets into configurable chunks
- [ ] Aggregate child progress into the parent job
- [ ] Keep queue management at the parent-job level

## Phase 6: Deep Enrichment Follow-Up Workflow

Commit point: `Add follow-up enrichment scans for discovered hosts`

### Scope

- Add a follow-up action to deepen investigation after a quick or balanced scan.
- Support enrichment targets such as:
  - new hosts from the latest scan
  - selected assets
  - unresolved or unknown assets
- Make AI optional and suited for post-inventory enrichment instead of slowing the first pass.

### Likely Files

- `backend/app/api/routes/scans.py`
- `backend/app/scanner/pipeline.py`
- `frontend/src/app/assets/page.tsx`
- `frontend/src/app/scans/page.tsx`

### Outcome

Argus can collect baseline inventory quickly and then deepen analysis as a deliberate second step.

Checklist:

- [ ] Add follow-up enrichment action after quick or balanced scans
- [ ] Support enrichment for new hosts from the latest scan
- [ ] Support enrichment for selected assets
- [ ] Support enrichment for unresolved or unknown assets
- [ ] Make AI optional for the follow-up flow

## Recommended Implementation Order

1. Phase 1: Scan Modes
2. Phase 2: Per-Stage Live Persistence
3. Phase 3: Results-So-Far UX
4. Phase 4: Performance Settings
5. Phase 5: Chunked Parent/Child Scan Jobs
6. Phase 6: Deep Enrichment Follow-Up Workflow

## Why This Order

- The first meaningful UX win comes from adding fast scan modes and showing results earlier.
- Live persistence and progressive counters improve perceived speed without a major orchestration rewrite.
- Parent/child chunk orchestration is more invasive and should come after incremental persistence is already working.
- Deep enrichment workflows are most useful once quick baseline scanning is stable.

## Success Metrics By Phase

### Phase 1

- Time to first visible host
- Total quick-scan duration

### Phase 2

- Time to first persisted asset
- Number of mid-scan asset updates

### Phase 3

- Quality of in-progress scan visibility
- Fewer “stuck scan” support issues

### Phase 4

- Ability to tune scan behavior without code changes
- Better scan performance across different network sizes

### Phase 5

- Time to first completed chunk
- Stability of queued and chunked scans

### Phase 6

- Time from first inventory to useful enrichment
- Reduction in `unknown` assets after follow-up scans

## Recommended First Delivery

The highest-value first delivery is:

1. Phase 1
2. Phase 2
3. Phase 3

That combination should make scans feel significantly faster before deeper orchestration changes are introduced.
