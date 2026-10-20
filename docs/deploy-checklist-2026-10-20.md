# Deploy checklist: security pass and Phases 3 and 4 (2026-10-20)

Everything below is committed on local `main` in both repos. **Nothing has been
pushed or deployed.**

| Repo | Local `main` | Contains |
|---|---|---|
| Argus | `0efd727` | security pass (`0bd08cf`), findings lifecycle (`098aebd`), Security page (`40cbaf1`) |
| InSOC | `e682e9b` | findings sync with Argus (`2740f60`) |

Checks run before merging:
- Argus: 282 backend tests and ruff; frontend lint, type-check and build.
- InSOC: 125 tests.
- Cross-repo end to end, 15 checks, against a real Argus backend, a real InSOC app
  and a production frontend build.

## 0. Before you start

- Migrations `20261020_0040` (`users.token_version`) and `20261020_0041` (finding
  lifecycle columns) run automatically when the backend starts. Both only add
  columns.
- **Everyone is signed out once.** Sessions move from `localStorage` to an
  httpOnly cookie, and tokens now carry a version. Sign in again after the deploy.
- Do the Dockhand secret steps (review #7/#8, in `docs/review-2026-10-20.md`) in
  the same sitting, so you only redeploy each stack once.

## 1. Argus

1. Push: `git -C C:/Users/nelso/Documents/Coding/argus push origin main`
2. Wait for the **Release Images** workflow to go green (backend, frontend, scanner).
3. Dockhand → `argus` → Environment:
   - add `INSOC_URL` = `http://192.168.100.20:8765`
   - add `INSOC_API_TOKEN` = InSOC's `INSOC_API_TOKEN` value, **secret**
   - review #7/#8: new `APP_SECRET_KEY` without `$` (e.g. `openssl rand -hex 32`),
     **secret**; mark `POSTGRES_PASSWORD`, `DATABASE_URL_DOCKER`,
     `SCANNER_DATABASE_URL`, `SNMP_V3_AUTH_KEY`, `SNMP_V3_PRIV_KEY` **secret**
     (values unchanged)
4. Redeploy. Re-pull is already on for this stack.
5. Check:
   - `curl http://192.168.100.20:8000/health` returns `ok`
   - the backend log shows the two migrations ran
   - after signing in, **Security** appears in the sidebar and lists incidents

## 2. InSOC

1. Push: `git -C C:/Users/nelso/Documents/Coding/insoc push origin main`
2. Dockhand → `insoc` → Environment: nothing new is required.
   - `ARGUS_PUSH_FINDINGS` defaults to `true`.
   - Docker findings attach to the host in `ARGUS_URL` (`192.168.100.20`). Set
     `ARGUS_DOCKER_HOST` only if HomePod is known to Argus under another address.
   - The existing `ARGUS_API_KEY` belongs to the `insoc` service user, which is
     what the sync needs.
   - Review #8: mark `INSOC_API_TOKEN` **secret**.
3. Redeploy (it builds on deploy).
4. Check: after the next sweep (hourly), Argus → Findings → source **InSOC**
   lists InSOC's findings. Acknowledge one there; the following sweep should list
   it as acknowledged and not alert.

## 3. If something goes wrong

- Argus snapshots of the pre-deploy stack are in
  `C:\Users\nelso\Documents\Coding\_Skills\dockhand_skill\snapshots\`. Take a
  fresh one before this deploy.
- Rolling back the code means redeploying the previous commit (`7930156`). The new
  columns are additive, so the old code ignores them; no downgrade migration is
  needed.
- InSOC keeps running if Argus is down: the sync is best-effort and only logs
  `argus push failed` / `argus ack sync failed`.
