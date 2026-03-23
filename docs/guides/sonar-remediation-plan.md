---
id: sonar-remediation-plan
title: Sonar Remediation Plan
---

# Sonar Remediation Plan

This plan tracks the current Sonar backlog in severity order and groups work into batches that lower operational risk first, then reduce long-term maintenance drag.

## Current Snapshot

The counts below are from the latest completed SonarCloud analysis on `main` for commit `2cf3f62` on March 23, 2026.

Quality gate status:

- `ERROR`
- failing condition: `new_coverage` = `61.6%` against an `80%` threshold
- new-code baseline date: `2026-03-21T01:36:56+0000`

Project measures:

- `BUGS`: `0`
- `VULNERABILITIES`: `0`
- `CODE_SMELLS`: `53`
- `COVERAGE`: `57.5%`
- `DUPLICATED_LINES_DENSITY`: `0.0%`

Open code-smell severity mix:

- `CRITICAL`: `14`
- `MAJOR`: `21`
- `MINOR`: `18`

Most common remaining rules:

- `python:S3776` Cognitive complexity is too high (`14`)
- `python:S1172` Remove unused function parameters (`6`)
- `typescript:S6759` Mark component props as read-only (`5`)
- `typescript:S3358` Extract nested ternary operations (`4`)
- `python:S3358` Extract nested conditional expressions (`3`)

Most concentrated remaining files:

- `backend/app/db/upsert.py` (`5`)
- `backend/app/scanner/stages/deep_probe.py` (`3`)
- `frontend/src/components/dashboard/RecentAssets.tsx` (`3`)
- `frontend/src/components/scans/ScanHistory.tsx` (`3`)
- `backend/app/api/routes/scans.py` (`2`)
- `backend/app/scanner/agent/tools.py` (`2`)
- `backend/app/scanner/pipeline.py` (`2`)
- `backend/app/scanner/probes/mdns.py` (`2`)
- `backend/app/scanner/snmp.py` (`2`)
- `backend/app/scanner/stages/fingerprint.py` (`2`)

## Remaining Backlog By Severity And Phase

### `CRITICAL`

- All `14` remaining critical code smells are backend `python:S3776` complexity items.
- Highest-risk files:
  - `backend/app/db/upsert.py` (`4`)
  - `backend/app/scanner/stages/fingerprint.py`
  - `backend/app/scanner/pipeline.py`
  - `backend/app/modules/tplink_deco.py`
  - `backend/app/scanner/stages/discovery.py`
  - `backend/app/fingerprinting/evidence.py`
  - `backend/app/scanner/stages/portscan.py`
  - `backend/app/scanner/agent/anthropic_analyst.py`
  - `backend/app/scanner/agent/ollama_analyst.py`
  - `backend/app/scanner/agent/tools.py`
  - `backend/app/scanner/probes/mdns.py`

### `MAJOR`

- `21` major code smells remain.
- Backend major backlog is now mostly:
  - `python:S1172` unused parameters
  - `python:S3358` nested conditional cleanup
  - `python:S8415` missing documented HTTPException responses
  - `python:S7483` timeout handling in `deep_probe.py`
  - `python:S107` parameter explosion in `scanner/config.py`
  - `python:S5843` regex complexity in `fingerprinting/internet_lookup.py`
  - `python:S5886` return type mismatch in `db/upsert.py`
- Frontend major backlog is now concentrated in:
  - `frontend/src/app/scans/page.tsx`
  - `frontend/src/components/dashboard/DeviceTypeChart.tsx`
  - `frontend/src/components/dashboard/RecentAssets.tsx`
  - `frontend/src/components/scans/ScanHistory.tsx`
  - `frontend/src/app/assets/page.tsx`
  - `frontend/src/types/index.ts`

### `MINOR`

- `18` minor code smells remain.
- Frontend minor backlog is dominated by:
  - `typescript:S6759` read-only props (`5`)
  - `typescript:S7735` negated conditions (`3`)
  - `typescript:S7764` prefer `globalThis.window` (`2`)
- Backend minor backlog is dominated by:
  - `python:S7503` async functions without async behavior (`3`)
  - one-off cleanup rules such as `python:S6353`

## Remediation Strategy

The order below follows a security and risk-management lens:

1. Recover the quality gate by raising new-code backend coverage above `80%`.
2. Refactor the remaining backend complexity hotspots.
3. Clear the concentrated frontend major/minor maintainability issues.
4. Finish backend API-contract and tail-cleanup items.

## Batch 0: Quality Gate Recovery

Priority: immediate

Target gate:

- `new_coverage >= 80%`

Current state:

- `new_coverage`: `61.6%`
- `new_lines_to_cover`: `1369`
- `new_uncovered_lines`: `474`
- `new_code_smells`: `8`

Approach:

- Add focused backend tests for the active code added since the March 21 baseline.
- Prioritize branch-heavy paths already being refactored because they are the most likely to carry uncovered new lines.
- Use targeted tests instead of broad end-to-end tests to raise coverage quickly and keep failures local.

Likely target modules for immediate test additions:

- `backend/app/scanner/pipeline.py`
- `backend/app/modules/tplink_deco.py`
- `backend/app/scanner/stages/fingerprint.py`
- `backend/app/scanner/stages/deep_probe.py`
- `backend/app/db/upsert.py`

Outcome:

- Restores merge confidence by making the quality gate meaningful again.

## Batch 1: FastAPI `Annotated` Migration

Priority: complete

Target rule:

- `python:S8410`

Target files:

- `backend/app/api/routes/assets.py`
- `backend/app/api/routes/auth.py`
- `backend/app/api/routes/scans.py`
- `backend/app/api/routes/system.py`
- `backend/app/api/routes/findings.py`
- `backend/app/api/routes/topology.py`

Approach:

- Replace `Depends(...)` route parameters with shared `Annotated[...]` aliases.
- Replace `Query(...)` route parameters with `Annotated[...]` query aliases where needed.
- Prefer local aliases like `DBSession`, `AdminUser`, and `CurrentUser` to keep signatures readable.

Status:

- Completed.
- No remaining `python:S8410` items are present in the latest scan.
## Batch 2: Critical Complexity Reduction

Priority: high

Target rule:

- `python:S3776`

Remaining target files:

- `backend/app/db/upsert.py`
- `backend/app/scanner/stages/fingerprint.py`
- `backend/app/scanner/pipeline.py`
- `backend/app/modules/tplink_deco.py`
- `backend/app/scanner/stages/discovery.py`
- `backend/app/fingerprinting/evidence.py`
- `backend/app/scanner/stages/portscan.py`
- `backend/app/scanner/agent/anthropic_analyst.py`
- `backend/app/scanner/agent/ollama_analyst.py`
- `backend/app/scanner/agent/tools.py`
- `backend/app/scanner/probes/mdns.py`

Approach:

- Extract branch-heavy logic into small helpers.
- Separate validation, state transitions, and serialization.
- Prefer guard clauses over deep nesting.

Risk reduction:

- Makes queue control, pause/cancel behavior, and sync flows easier to reason about and safer to change.

Status:

- First pass completed in queue-control and frontend hotspot areas.
- The current scan confirms the remaining complexity backlog has shifted into lower-level scanner, evidence, and upsert modules.

## Batch 3: API Contract Hygiene

Priority: medium

Target rules:

- `python:S8415`
- `python:S3358`

Remaining target files:

- `backend/app/api/routes/assets.py`
- `backend/app/api/routes/scans.py`
- `backend/app/scanner/probes/mdns.py`

Approach:

- Add `responses={...}` metadata for documented `HTTPException` paths.
- Replace nested conditional expressions with explicit branches.

Risk reduction:

- Improves API clarity for operators and future automation.
- Makes failure modes explicit in generated docs and client expectations.

Status:

- Primary response metadata pass completed.
- Residual work is now one `python:S8415` item and a small set of nested-conditional cleanups.

## Batch 4: Frontend Accessibility And Deprecation Cleanup

Priority: medium

Target files:

- `frontend/src/app/scans/page.tsx`
- `frontend/src/components/dashboard/DeviceTypeChart.tsx`
- `frontend/src/components/dashboard/RecentAssets.tsx`
- `frontend/src/components/scans/ScanHistory.tsx`
- `frontend/src/app/assets/page.tsx`
- `frontend/src/types/index.ts`
- `frontend/src/app/layout.tsx`
- `frontend/src/app/providers.tsx`
- `frontend/src/components/dashboard/ActivityFeed.tsx`
- `frontend/src/components/dashboard/StatsGrid.tsx`
- `frontend/src/components/layout/AppShell.tsx`
- `frontend/src/hooks/useAuth.ts`
- `frontend/src/hooks/useWebSocket.ts`
- `frontend/src/components/topology/TopologyMap.tsx`

Approach:

- Remove the remaining nested ternaries and negated conditions.
- Finish read-only prop typing across shared components.
- Replace `window` references with `globalThis.window`.
- Remove array-index keys and small dashboard-list maintainability issues.
- Clean up the two type-shape issues in `frontend/src/types/index.ts`.

Risk reduction:

- Reduces operator error risk in setup and administration workflows.
- Lowers maintenance friction in the most interactive screens.

Current severity mix:

- `MAJOR`: 6
- `MINOR`: 13

Status:

- Major first pass completed.
- The latest scan confirms `frontend/src/app/settings/page.tsx`, `frontend/src/components/assets/AssetTable.tsx`, and most prior hotspot files are no longer dominant backlog drivers.
- Remaining frontend work is now a short residual pass, not a full hotspot refactor batch.

## Batch 5: Tail Cleanup

Priority: low

Examples:

- Replace duplicated string literals with constants.
- Remove unused parameters.
- Normalize naming and small maintainability issues.
- Tackle residual backend rules such as:
  - `python:S7483`
  - `python:S1192`
  - `python:S1172`
  - `python:S117`

Risk reduction:

- Keeps the backlog from re-accumulating and improves local readability.

Current severity mix:

- `CRITICAL`: 14
- `MAJOR`: 15
- `MINOR`: 5

Status:

- In progress.
- Remaining Batch 5 work is now mostly backend residual rules:
  - `python:S1172`
  - `python:S7503`
  - `python:S5843`
  - `python:S5886`
  - `python:S7483`
  - `python:S6353`
  - `python:S107`

## Verification Gates

Each batch should end with focused validation:

- `python3 -m py_compile` for touched backend files
- targeted backend tests where behavior changes
- frontend lint or build checks for touched UI files
- refreshed Sonar export after meaningful batches

## Progress Log

- [x] Batch 0: SonarCloud latest run captured from GitHub Actions and Sonar API
- [ ] Batch 0: raise `new_coverage` from `61.6%` to `80%+`
- [x] Batch 1: first `Annotated` migration pass across backend route modules
- [ ] Batch 2: remaining backend complexity hotspots
- [x] Batch 3: API contract cleanup
- [ ] Batch 4: residual frontend maintainability cleanup
- [ ] Batch 5: tail cleanup
