---
id: sonar-remediation-plan
title: Sonar Remediation Plan
---

# Sonar Remediation Plan

This plan tracks the current Sonar backlog in severity order and groups work into batches that lower operational risk first, then reduce long-term maintenance drag.

## Current Snapshot

The counts below are from the last completed Sonar export. Additional frontend and tail-cleanup work has landed locally since then and still needs a fresh Sonar run to confirm the new totals.

- `BLOCKER`: 1
- `CRITICAL`: 46
- `MAJOR`: 92
- `MINOR`: 88
- `VULNERABILITY`: 10
- `CODE_SMELL`: 217

Most common rules in the current export:

- `typescript:S6759` Frontend maintainability issues
- `python:S3776` Cognitive complexity is too high
- `typescript:S3358` Nested conditional expressions should be simplified
- `typescript:S6772` React props and state maintainability issues
- `python:S7483` Python maintainability issues

Most concentrated files:

- `frontend/src/app/settings/page.tsx`
- `frontend/src/components/scans/ScanHistory.tsx`
- `frontend/src/app/assets/[id]/page.tsx`
- `frontend/src/components/assets/AssetTable.tsx`
- `frontend/src/app/login/page.tsx`
- `backend/app/workers/tasks.py`

## Remaining Backlog By Severity And Phase

### `BLOCKER`

Batch 5: Tail cleanup

- `1` blocker remains outside the completed backend route and API-contract batches.

Status update:

- The remaining blocker in `backend/app/core/config.py` has been fixed locally by removing the hard-coded database password default and deriving `DATABASE_URL` from environment-backed settings.
- A fresh Sonar run is required to clear the count in this section.

### `CRITICAL`

Batch 2 follow-up: Backend complexity reduction

- `27` critical issues remain, concentrated in:
  - `backend/app/workers/tasks.py`
  - `backend/app/modules/tplink_deco.py`
  - `backend/app/scanner/pipeline.py`

Batch 5: Tail cleanup

- `15` critical issues remain in backend modules and probe helpers outside the completed route batches.

Batch 4: Frontend accessibility and maintainability

- `4` critical frontend issues remain.

Status update:

- The highest-risk frontend hotspots have been addressed locally in:
  - `frontend/src/app/login/page.tsx`
  - `frontend/src/app/settings/page.tsx`
  - `frontend/src/components/scans/ScanHistory.tsx`
  - `frontend/src/components/assets/AssetTable.tsx`
  - `frontend/src/app/assets/[id]/page.tsx`
- A fresh Sonar run is required to confirm how many critical findings remain after the latest refactors.

### `MAJOR`

Batch 4: Frontend accessibility and maintainability

- `63` major issues remain.
- Highest concentration:
  - `frontend/src/app/settings/page.tsx`
  - `frontend/src/components/scans/ScanHistory.tsx`
  - `frontend/src/app/assets/[id]/page.tsx`
  - `frontend/src/components/assets/AssetTable.tsx`

Batch 5: Tail cleanup

- `24` major backend cleanup items remain.

Batch 3 follow-up: API contract hygiene

- `3` major API-contract cleanup items remain.

Batch 2 follow-up: Backend complexity reduction

- `2` major complexity items remain after the first refactor sweep.

### `MINOR`

Batch 4: Frontend accessibility and maintainability

- `77` minor frontend issues remain.

Batch 2 follow-up: Backend complexity reduction

- `6` minor backend maintainability issues remain.

Batch 5: Tail cleanup

- `5` minor cleanup items remain.

## Remediation Strategy

The order below follows a security and risk-management lens:

1. Remove real defects and correctness risks.
2. Eliminate high-volume blockers that obscure the true backlog.
3. Refactor high-complexity control paths that affect scan execution and operator actions.
4. Clean up API contracts and frontend accessibility gaps.
5. Finish low-cost maintainability cleanup.

## Batch 0: Correctness Fixes

Priority: immediate

- Fix the `_investigate_host(...)` call mismatch in `backend/app/api/routes/assets.py`.
- Confirm route behavior still works after the fix with focused backend validation.

Outcome:

- Clears the one known `BUG`/correctness-style blocker before broader cleanup.

## Batch 1: FastAPI `Annotated` Migration

Priority: high

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

Risk reduction:

- Lowers blocker volume quickly without changing endpoint behavior.
- Standardizes dependency declarations, which reduces accidental drift across route modules.

## Batch 2: Critical Complexity Reduction

Priority: high

Target rule:

- `python:S3776`

Remaining target files:

- `backend/app/workers/tasks.py`
- `backend/app/modules/tplink_deco.py`
- `backend/app/scanner/pipeline.py`

Approach:

- Extract branch-heavy logic into small helpers.
- Separate validation, state transitions, and serialization.
- Prefer guard clauses over deep nesting.

Risk reduction:

- Makes queue control, pause/cancel behavior, and sync flows easier to reason about and safer to change.

Status:

- First pass completed in `scans.py`, `tasks.py`, and `pipeline.py`.
- Follow-up work remains in the same files plus `tplink_deco.py`.

## Batch 3: API Contract Hygiene

Priority: medium

Target rules:

- `python:S8415`
- `python:S3358`

Remaining target files:

- backend route handlers still carrying undocumented edge-case responses after the first decorator pass

Approach:

- Add `responses={...}` metadata for documented `HTTPException` paths.
- Replace nested conditional expressions with explicit branches.

Risk reduction:

- Improves API clarity for operators and future automation.
- Makes failure modes explicit in generated docs and client expectations.

Status:

- Primary response metadata pass completed in `assets.py`, `scans.py`, and `system.py`.
- Only a small residual set remains.

## Batch 4: Frontend Accessibility And Deprecation Cleanup

Priority: medium

Target files:

- `frontend/src/app/settings/page.tsx`
- `frontend/src/app/login/page.tsx`
- `frontend/src/components/scans/ScanHistory.tsx`
- `frontend/src/components/assets/AssetTable.tsx`
- `frontend/src/app/assets/[id]/page.tsx`
- `frontend/src/app/scans/page.tsx`
- `frontend/src/hooks/useAuth.ts`
- `frontend/src/components/scans/QuickScan.tsx`
- `frontend/src/lib/api.ts`

Approach:

- Fix label-to-control associations.
- Replace deprecated form event patterns.
- Simplify conditional rendering patterns flagged by Sonar.

Risk reduction:

- Reduces operator error risk in setup and administration workflows.
- Lowers maintenance friction in the most interactive screens.

Current severity mix:

- `CRITICAL`: 4
- `MAJOR`: 63
- `MINOR`: 77

Status:

- Primary pass completed locally.
- Changes include:
  - proper `label` / `htmlFor` associations in the login and setup forms
  - replacement of deprecated `FormEvent`-style handlers with form submit handler types derived from component props
  - extraction of nested scan-row and filter-menu logic in `ScanHistory.tsx` and `AssetTable.tsx`
  - checkbox label text wrapped in elements to eliminate ambiguous JSX spacing issues
  - readonly prop typing applied across the main frontend hotspot components
  - array-index keys removed from the major list/skeleton hotspots in the asset detail view and scan history
- Remaining frontend cleanup should be treated as residual follow-up after the next Sonar run, not as untouched Batch 4 work.

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

- `BLOCKER`: 1
- `CRITICAL`: 15
- `MAJOR`: 24

Status:

- In progress.
- Completed locally so far:
  - duplicate literal cleanup in backend route/model hotspots
  - tail cleanup in frontend hotspot files while doing Batch 4, including readonly props, stable keys, and smaller JSX simplifications
  - Docusaurus dependency alignment plus `serialize-javascript@7.0.4` override in `website/package.json`, with docs build passing and `npm audit` returning zero vulnerabilities
- Remaining Batch 5 work is now mostly backend residual rules and any frontend stragglers left after the next Sonar refresh.
- `MINOR`: 5

## Verification Gates

Each batch should end with focused validation:

- `python3 -m py_compile` for touched backend files
- targeted backend tests where behavior changes
- frontend lint or build checks for touched UI files
- refreshed Sonar export after meaningful batches

## Progress Log

- [x] Batch 0: `_investigate_host(...)` call mismatch identified
- [x] Batch 0: correctness fix implemented
- [x] Batch 1: first `Annotated` migration pass across backend route modules
- [x] Batch 2: complexity refactors in scan-control code
- [x] Batch 3: API contract cleanup
- [ ] Batch 4: frontend accessibility cleanup
- [ ] Batch 5: tail cleanup
