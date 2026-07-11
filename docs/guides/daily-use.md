---
id: daily-use
title: Daily Use Guide
sidebar_position: 17
---

# Daily Use Guide

Argus is designed to start with the dashboard. The dashboard's Operator Brief
turns inventory, scan, finding, and integration state into a short operational
queue.

## Daily Questions

Use the Operator Brief to answer these questions in order:

| Question | Where to Look | What to Do |
|---|---|---|
| What changed? | Changed | Review new assets, scan-driven inventory changes, and recent updates. |
| What needs attention? | Needs Attention | Fix failed scans, failed syncs, offline assets, and failed backups. |
| What is unknown? | Unknowns | Resolve missing hostnames, vendors, device types, weak classifications, and weak topology. |
| What is risky? | Risk | Review critical/high findings, high-risk exposed services, and unsupported lifecycle records. |
| What should I do next? | Recommended Actions | Follow the highest-priority action link. |

## Recommended Workflow

1. Open **Dashboard**.
2. Review **Recommended Actions** first.
3. Work through **Risk** and **Needs Attention** before general inventory review.
4. Use **Unknowns** as the cleanup queue for better fingerprinting and topology.
5. Open individual assets when a recommendation points to evidence, ports, SNMP,
   AI analysis, or lifecycle details.
6. Open **Topology** when a recommendation points to weak or unconfirmed network
   relationships.

## Interpreting Brief Items

Each brief item includes:

- severity
- reason
- target type
- recommended action
- route into the relevant workflow

Viewer accounts can read the brief. Admin-only actions are marked instead of
executed for viewer accounts.

## Empty States

An empty section is useful signal. For example:

- no **Risk** items means there are no currently open critical or high findings
  in the brief window
- no **Needs Attention** items means there are no failed scans, failed syncs,
  offline assets, stale assets, or failed backups selected for the brief
- no **Unknowns** means Argus currently has enough identity and topology evidence
  for the assets in scope

## Related Docs

- [Operator Experience Plan](./operator-experience-plan.md)
- [Frontend Dashboard Guide](./frontend-dashboard.md)
- [Topology Evidence and Correction](./topology-evidence.md)
