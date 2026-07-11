---
id: operator-experience-plan
title: Operator Experience and Evidence-First Topology Plan
sidebar_position: 16
---

# Operator Experience and Evidence-First Topology Plan

This plan defines the next Argus product refinement phase. The goal is not to
add unrelated capabilities. The goal is to make the existing inventory,
scanning, findings, topology, and integration features work together as a
clear daily-use operator experience.

Argus should help a homelab or small-network operator understand what changed,
what matters, why Argus believes it, and what to do next.

## Product Direction

Argus is an operator console for small private networks. It should answer five
daily questions quickly:

- What changed?
- What needs attention?
- What is unknown?
- What is risky?
- What should I do next?

Topology has a related but more specific promise:

- Every topology relationship has a source.
- Every relationship is classified as observed, inferred, or manual.
- Every relationship has confidence.
- The UI can explain why two devices are connected.
- The operator can correct or suppress wrong relationships.

## Non-Goals

This phase should avoid broad feature expansion.

- Do not redesign the whole application shell.
- Do not replace the topology renderer before the graph is explainable.
- Do not build enterprise campus, WAN, SD-WAN, or packet-level topology features.
- Do not add new third-party integrations unless they directly support the
  operator brief or topology evidence model.
- Do not make the dashboard a static reporting page; every important item should
  lead to a useful next action.

## Experience Principles

### Action Beats Status

Counts and charts are useful only when they help the operator decide what to do.
The dashboard should prioritize unresolved work, new changes, and weak evidence
over passive summaries.

### Evidence Beats Assertion

Argus should avoid unexplained claims. Device classifications, topology
relationships, risk labels, and recommended actions should expose their source
evidence whenever practical.

### Correction Is Part of Discovery

Small networks often expose incomplete or misleading data. Manual correction is
not an edge case; it is part of making the product trustworthy. Manual topology
and identity corrections should be durable, auditable, and visible.

### Uncertainty Should Be Useful

Unknown devices, low-confidence fingerprints, stale assets, missing evidence,
and inferred topology links are work queues. The UI should group them and
suggest specific resolution actions.

## Workstream 1: Daily Use Path

The dashboard should become an operator brief before it is a chart page.

### Operator Brief

Add a backend-generated operator brief with sections that directly map to the
daily questions.

#### Changed Since Last Visit

Candidate signals:

- new assets
- assets newly offline or newly active
- hostname, vendor, OS, or device type changes
- new open ports
- new or changed findings
- completed scans with material inventory changes
- integration syncs that changed assets or wireless associations

#### Needs Attention

Candidate signals:

- critical or high findings
- failed scans
- failed integration syncs
- stale assets
- failed config backups
- paused or stuck scan jobs
- assets with weak evidence or low classification confidence

#### Unknowns

Candidate signals:

- unknown device type
- missing vendor
- missing hostname
- assets with shallow scan evidence only
- missing SNMP evidence on likely network gear
- unresolved topology role
- inferred topology links with low confidence

#### Risk

Candidate signals:

- open high-risk services
- imported high-severity findings
- default or weak protocol exposure indicators
- unsupported or end-of-life lifecycle records
- public or unexpected service exposure if that signal exists

#### Recommended Actions

Each recommendation should include:

- title
- reason
- target type and target id when applicable
- severity or priority
- action route
- optional action payload for one-click workflows

Examples:

- Run deep enrichment on unknown devices.
- Refresh SNMP on likely routers, switches, and access points.
- Review new high-risk findings.
- Open the autopsy trace for low-confidence classifications.
- Review unconfirmed topology links.
- Open failed scan details.

### Implementation Shape

Recommended backend files:

- `backend/app/services/operator_brief.py`
- `backend/app/api/routes/system.py`
- backend tests under `backend/tests/`

Recommended frontend files:

- `frontend/src/lib/api.ts`
- `frontend/src/types/index.ts`
- `frontend/src/hooks/`
- `frontend/src/components/dashboard/`
- `frontend/src/app/dashboard/page.tsx`

Recommended API:

```http
GET /api/v1/system/operator-brief
```

The endpoint should return a compact response purpose-built for the dashboard.
It should not require the frontend to fetch all assets, all scans, all findings,
and all integrations independently.

## Workstream 2: Evidence-First Topology

Topology should become explainable before it becomes more visually ambitious.
The current graph can remain visually familiar while the data contract and
inspector experience become stronger.

### Topology Relationship Contract

Every topology edge returned to the UI should expose:

- `relationship_type`
- `source`
- `observed`
- `confidence`
- `last_seen`
- `evidence`
- `local_interface`
- `remote_interface`
- `ssid`
- `segment_id`
- `manual_override`
- `suppressed`

The important operator distinction is:

| Kind | Meaning |
|---|---|
| Observed | Direct evidence from SNMP, UniFi, Deco, wireless association, controller data, or another concrete source. |
| Inferred | Argus derived the relationship from weaker signals such as subnet, role, ARP, or heuristics. |
| Manual | The operator created or corrected the relationship. |

### Edge Inspector

Clicking a topology edge should answer:

- What relationship is this?
- Is it observed, inferred, or manual?
- What confidence does Argus have?
- What source produced it?
- When was it last seen?
- What exact evidence supports it?
- What can I do if this is wrong?

Useful actions:

- confirm inferred link
- suppress inferred link
- edit manual link
- delete manual link
- open related asset
- open evidence detail

### Node Inspector

Clicking a topology node should answer:

- What asset is this?
- What topology role does Argus think it has?
- How confident is that role?
- Which segment does it belong to?
- What are its parent, uplink, or gateway candidates?
- Which clients or child devices depend on it?
- What evidence is missing?

Useful actions:

- open asset detail
- run deep enrichment
- refresh SNMP
- assign topology role
- create manual relationship
- review autopsy trace

### Correction Workflow

Topology correction should be durable and auditable.

Required correction actions:

- confirm inferred relationship
- suppress wrong inferred relationship
- create manual relationship
- edit manual relationship
- delete manual relationship
- assign or clear preferred topology role
- reset manual correction where needed

Manual corrections should take precedence over inferred links unless the
operator explicitly clears the correction.

## Phased Delivery

### Phase 1: Product Contract

Status: this document.

Deliverables:

- define the daily-use product promises
- define the evidence-first topology promises
- identify non-goals
- define workstreams and delivery order

### Phase 2: Operator Brief Backend

Deliverables:

- add operator brief service
- add compact operator brief API endpoint
- add backend tests for changed, attention, unknown, risk, and recommended action buckets
- avoid full-inventory dashboard fanout where possible

Validation:

- unit tests for bucket classification
- route contract test for response shape
- smoke test with an empty database
- smoke test with representative assets, scans, findings, and integration sync state

### Phase 3: Operator Brief Dashboard

Deliverables:

- add dashboard brief panel
- make the brief the top dashboard story
- link every recommendation to a useful page or action
- keep existing charts and summaries as supporting context

Validation:

- frontend type-check
- dashboard empty state
- dashboard populated state
- viewer role can read brief but cannot trigger admin-only actions

### Phase 4: Topology Evidence API

Deliverables:

- reconcile topology edge serializer fields
- expose observed, inferred, and manual relationship metadata
- add TypeScript types for topology evidence
- keep existing graph rendering compatible

Validation:

- route tests for observed edge
- route tests for inferred edge
- route tests for manual edge
- frontend type-check

### Phase 5: Topology Inspectors

Deliverables:

- edge inspector panel
- node inspector panel
- source, confidence, last-seen, and evidence display
- links from topology to asset details, autopsy, SNMP refresh, and enrichment actions

Validation:

- inspect observed wireless link
- inspect inferred same-segment link
- inspect manual link
- inspect asset node with missing evidence

### Phase 6: Correction Workflow

Deliverables:

- confirm inferred link
- suppress inferred link
- create and edit manual links
- assign topology role override
- audit or history entries for manual corrections

Validation:

- correction survives refresh
- suppressed link stays hidden unless requested
- manual link wins over inferred link
- viewer role cannot mutate topology

### Phase 7: Daily Use and Topology Docs

Deliverables:

- daily-use guide
- topology evidence guide
- correction workflow guide
- troubleshooting entries for common scanner and topology evidence gaps

Validation:

- docs build
- links from dashboard and topology UI point to relevant help where appropriate

## Suggested Branches and Commits

Recommended branch:

```text
feature/operator-experience
```

Suggested commit sequence:

```text
docs(product): define operator experience plan
feature(brief): add operator brief service and api
feature(dashboard): surface operator brief actions
refactor(topology): expose evidence metadata in graph api
feature(topology): add edge and node inspectors
feature(topology): add correction workflow
docs(topology): document evidence and correction flows
```

## Success Criteria

This refinement phase is successful when:

- the dashboard can be used as a daily operational starting point
- important dashboard items link to concrete workflows
- unknowns and weak evidence are visible as work queues
- topology edges explain source, confidence, and last-seen state
- wrong topology links can be corrected without editing the database
- manual topology corrections survive future scans
- the docs explain how operators should use the improved flow

## Related Docs

- [Frontend Dashboard Guide](./frontend-dashboard.md)
- [Topology Engineering Plan](./topology-engineering-plan.md)
- [Fingerprinting Guide](./fingerprinting.md)
- [Settings Reference](./settings-reference.md)
- [Performance, Architecture, and Functional Improvement Roadmap](./improvement-roadmap.md)
