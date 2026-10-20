# InSOC Integration

Argus is the system of record (assets, ports, topology, findings). InSOC, the
agentic SOC, is the reasoning and action layer. They talk over Argus's API and
webhooks; the codebases and databases stay separate.

## Service account

Create a user with role **Service (integrations)** in Settings → Users, then
open Settings → API Keys, pick that user in the **Owner** selector and create
the key. Admins can create, list and revoke keys on behalf of any user, so the
service account never needs to sign in or be promoted to admin. The same is
available via the API: `POST /api/v1/auth/api-keys` with `{"name": "...", "user_id": "<uuid>"}`.
A service account can:

- read everything a viewer can (assets, topology, findings), and
- call `POST /api/v1/findings/ingest`.

It cannot manage users, settings, scans or modules. Send the key as
`X-API-Key: <key>`.

## Webhook events

Set `NOTIFY_WEBHOOK_URL` (for example `http://insoc-orchestrator:8000/hooks/argus`)
and `NOTIFY_WEBHOOK_TOKEN`. Every post carries `Authorization: Bearer <token>`
and this envelope:

```json
{"event": "ports_changed", "data": {...}, "source": "argus", "sent_at": "2026-10-17T12:00:00+00:00"}
```

| Event | Fired from | `data` |
|---|---|---|
| `new_device` | scan pipeline | ip, mac, hostname, device_class, job_id |
| `devices_offline` | heartbeat/offline checks | `devices: [...]` |
| `ports_changed` | scan pipeline, when an existing asset's ports change | asset_id, ip, hostname, job_id, `changes: {"port_22/tcp": {"old","new"}}` |
| `new_findings` | findings ingest, newly created findings only | `findings: [{asset_id, ip, source_tool, external_id, title, severity}]` |

Each event has an alert rule (Settings → Alerts) that can disable it or toggle
webhook/email. `ports_changed` and `new_findings` default to webhook only.
Delivery failures are logged and never interrupt scans or ingest.

Both the `backend` and `scanner` containers need the webhook and SMTP
variables, because scan-time alerts fire from the scanner worker.

## Findings lifecycle (Phase 3)

Argus is the system of record for findings, including InSOC's. Each finding is
`open`, `acknowledged` (open, with `ack_until` in the future), `resolved` or
`ignored` (suppressed).

Re-ingesting a finding (same asset, `source_tool` and `external_id`; or same
title when there is no external id) applies these rules:

| Situation | Result |
|---|---|
| Seen again | `occurrences` +1, `last_seen` updated, title refreshed |
| Seen again after being resolved | reopened (`state: open`), acknowledgement cleared |
| Seen at a higher severity | escalated: acknowledgement cleared so it alerts again |
| Ignored | stays ignored whatever the severity |
| Listed in `resolved_external_ids` | resolved (`resolved_at` set) |

The ingest response adds `reopened`, `escalated` and `resolved` counts.

API (admin or service role):

- `POST /api/v1/findings/{id}/ack` `{"hours": 24, "note": "..."}`; leave out `hours`
  to acknowledge until the finding resolves.
- `POST /api/v1/findings/{id}/unack`
- `GET /api/v1/findings/?source_tool=insoc&external_id=<key>`
- `PATCH /api/v1/findings/{id}` `{"status": "open" | "resolved" | "ignored"}` (admin)

InSOC pushes after each recorded run, using the finding key as `external_id`, and
pulls acknowledgements before classifying. So acknowledging in either UI
silences re-alerts in both. Its key needs the **service** role.
