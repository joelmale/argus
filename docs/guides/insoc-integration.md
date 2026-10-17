# InSOC Integration

Argus is the system of record (assets, ports, topology, findings). InSOC, the
agentic SOC, is the reasoning and action layer. They talk over Argus's API and
webhooks; the codebases and databases stay separate.

## Service account

Create a user with role **Service (integrations)** in Settings → Users, then
create an API key for it. A service account can:

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
