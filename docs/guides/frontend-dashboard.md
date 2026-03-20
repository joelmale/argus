---
id: frontend-dashboard-guide
title: Frontend Dashboard Guide
sidebar_position: 12
---

# Frontend Dashboard Guide

`argus-frontend` is the operator-facing dashboard for inventory, scans, findings, topology, and settings.

## Primary Views

| Page | Purpose |
|---|---|
| `/dashboard` | high-level status and recent activity |
| `/assets` | searchable inventory table |
| `/assets/[id]` | detailed asset view |
| `/topology` | graph-based topology visualization |
| `/scans` | scan history, active progress, manual scan controls |
| `/findings` | finding review and status workflows |
| `/settings` | scanner, integrations, users, keys, and policies |
| `/login` | authentication entry point |

## Dashboard

The dashboard is intended to answer:

- what is happening right now
- what changed recently
- where should the operator focus first

Common elements include:

- status summaries
- recent assets
- activity feed
- findings summary
- device-type distribution

## Asset Inventory

The asset list supports:

- search
- status filtering
- export actions
- sortable and filterable columns

The detail page supports:

- overview
- open ports
- findings
- evidence
- AI analysis
- passive timeline
- lifecycle information
- backups
- tags and metadata
- autopsy trace

## Active Scan Management

The scans page includes:

- manual trigger controls
- live running state
- expanded active-scan detail pane
- stage and progress messaging

This view is critical when diagnosing long-running scans or target-resolution mistakes.

## Settings UX

The settings page is organized into grouped sections instead of one flat form.

Current sections cover:

- discovery engine
- automation
- access and control
- integrations

Examples of admin workflows:

- configure scanner ranges and behavior
- manage SNMP and passive listener settings
- enable AI fingerprint synthesis
- refresh fingerprint datasets
- manage users and API keys
- configure the TP-Link Deco module

## TP-Link Deco Views

The Deco module surface in Settings includes:

- enablement and connection configuration
- test connection
- sync now
- recent sync runs
- parsed issue and recommendation summaries
- downloadable log copy

## Frontend Development Notes

Development is normally run through Docker Compose, but the frontend itself is a standard Next.js application.

Useful commands:

```bash
cd frontend
npm run lint
npm run type-check
npm run build
```

## Example TypeScript Pattern

Avoid `any` in UI state and event handling.

```ts
type TplinkLogIssue = {
  key: string;
  title: string;
  severity: string;
  issue: string;
  recommendation: string;
  count: number;
  sample_lines: string[];
  affected_macs: string[];
};

type TplinkLogAnalysis = {
  health_score: number;
  event_count: number;
  issues: TplinkLogIssue[];
};
```

## Related Docs

- [Backend API Guide](./backend-api.md)
- [Troubleshooting](../troubleshooting.md)
