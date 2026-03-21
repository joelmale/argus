---
id: sonar-remediation-plan
title: Sonar Remediation Plan
---

# Sonar Remediation Plan

This plan tracks the current Sonar backlog in severity order and groups work into batches that lower operational risk first, then reduce long-term maintenance drag.

## Current Snapshot

- `BLOCKER`: 139
- `CRITICAL`: 51
- `MAJOR`: 120
- `MINOR`: 88

Most common rules in the current export:

- `python:S8410` FastAPI dependency injection should use `Annotated`
- `python:S3776` Cognitive complexity is too high
- `python:S8415` Route handlers should document `HTTPException` responses
- `typescript:S6759` Frontend maintainability issues
- `python:S7483` Python maintainability issues

Most concentrated files:

- `backend/app/api/routes/assets.py`
- `backend/app/api/routes/system.py`
- `frontend/src/app/settings/page.tsx`
- `backend/app/api/routes/auth.py`
- `frontend/src/components/scans/ScanHistory.tsx`
- `backend/app/api/routes/scans.py`

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

Target files:

- `backend/app/api/routes/scans.py`
- `backend/app/workers/tasks.py`
- `backend/app/scanner/pipeline.py`
- `backend/app/modules/tplink_deco.py`
- `frontend/src/components/scans/ScanHistory.tsx`

Approach:

- Extract branch-heavy logic into small helpers.
- Separate validation, state transitions, and serialization.
- Prefer guard clauses over deep nesting.

Risk reduction:

- Makes queue control, pause/cancel behavior, and sync flows easier to reason about and safer to change.

## Batch 3: API Contract Hygiene

Priority: medium

Target rules:

- `python:S8415`
- `python:S3358`

Target files:

- `backend/app/api/routes/assets.py`
- `backend/app/api/routes/scans.py`
- `backend/app/api/routes/system.py`

Approach:

- Add `responses={...}` metadata for documented `HTTPException` paths.
- Replace nested conditional expressions with explicit branches.

Risk reduction:

- Improves API clarity for operators and future automation.
- Makes failure modes explicit in generated docs and client expectations.

## Batch 4: Frontend Accessibility And Deprecation Cleanup

Priority: medium

Target files:

- `frontend/src/app/settings/page.tsx`
- `frontend/src/app/login/page.tsx`
- `frontend/src/components/scans/ScanHistory.tsx`
- `frontend/src/components/assets/AssetTable.tsx`
- `frontend/src/app/assets/[id]/page.tsx`

Approach:

- Fix label-to-control associations.
- Replace deprecated form event patterns.
- Simplify conditional rendering patterns flagged by Sonar.

Risk reduction:

- Reduces operator error risk in setup and administration workflows.
- Lowers maintenance friction in the most interactive screens.

## Batch 5: Tail Cleanup

Priority: low

Examples:

- Replace duplicated string literals with constants.
- Remove unused parameters.
- Normalize naming and small maintainability issues.

Risk reduction:

- Keeps the backlog from re-accumulating and improves local readability.

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
