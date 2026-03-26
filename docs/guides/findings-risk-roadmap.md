# Findings Risk Roadmap

This document captures a shelved roadmap for evolving Argus from a discovery-first tool into a more operationally useful risk and remediation platform. It is intentionally parked here so topology and network diagramming work can take priority.

## Goal

Turn the `Findings` area into a first-class cyber risk workflow that:

- normalizes security signals from scans, probes, AI analysis, and imported tools
- ranks issues by exposure, criticality, and confidence
- shows evidence and recommended actions
- supports real triage and remediation workflows

## Current Gap

Argus currently spreads important security context across several surfaces:

- asset ports and status live in Assets and Scans
- AI security observations live on the asset page
- imported vulnerability data lives in Findings
- there is little prioritization based on business criticality, exposure, or confidence

This means the user must do the correlation mentally. The long-term goal is for Argus to do that correlation automatically and present one actionable risk queue.

## Phase 1: Expand the Finding Model

Extend the `Finding` database model so findings are normalized risk records rather than mostly imported vulnerability rows.

### Proposed fields

- `category`
- `priority`
- `confidence`
- `state`
- `recommended_action`
- `why_it_matters`
- `evidence`
- `owner`
- `notes`
- `due_date`
- `first_detected_by`
- `last_detected_by`
- `suppressed`
- `suppression_reason`

### Keep for compatibility

- `severity`
- `source_tool`
- `cve`
- `port_number`
- `protocol`

### Proposed state model

- `open`
- `triaged`
- `in_progress`
- `resolved`
- `accepted_risk`
- `false_positive`
- `suppressed`

### Proposed category model

- `vulnerability`
- `weak_protocol`
- `exposed_service`
- `insecure_config`
- `management_exposure`
- `unsupported_software`
- `identity_risk`
- `network_exposure`
- `anomalous_device`
- `informational`

### Proposed priority model

- `critical`
- `high`
- `medium`
- `low`

### Deliverables

- Alembic migration
- API serializer updates
- frontend type updates

## Phase 2: Add Rule-Driven Finding Generation

Introduce a backend rule engine that creates findings from Argus scan evidence, not just imported tools.

### New backend modules

- `backend/app/findings/rules.py`
- `backend/app/findings/generator.py`

### Rule inputs

- asset type and device class
- open ports
- service banners
- SNMP evidence
- HTTP and TLS probe results
- AI asset analysis
- plugin and module evidence
- exposure context

### Initial built-in rules

1. Telnet detected
2. FTP detected
3. SNMP v1/v2c enabled
4. HTTP admin interface detected
5. HTTPS admin with self-signed or default cert
6. Exposed SSH, RDP, or WinRM management surface
7. UPnP on gateway or router
8. SMB exposed broadly
9. Unknown device with many open ports
10. Infrastructure asset stale or unexpectedly offline
11. Internet-exposed management port
12. Device class and vendor mismatch anomaly

### Behavior

- rules create or update normalized findings
- repeated detections refresh `last_seen`
- missing detections can later drive stale or auto-resolve logic

### Deliverables

- post-scan finding generation in the scan pipeline
- regression tests for each rule

## Phase 3: Add Asset Criticality and Context

Severity alone is not enough. Priority should depend on what the asset is, how exposed it is, and how important it is.

### Proposed asset fields

- `criticality`
- `environment`
- `internet_exposed`
- `management_plane`
- `crown_jewel`
- `expected_online`

### Why this matters

- a hypervisor and a game console should not rank equally
- SNMPv2 on a firewall is more important than SNMPv2 on a printer
- a stale infrastructure asset is more important than a stale media client

### Priority model

Use a composite priority calculation:

- technical severity
- exposure level
- asset criticality
- confidence

### Deliverables

- asset schema updates
- asset edit UI updates
- priority calculator service

## Phase 4: Redesign the Findings UI

Convert the Findings page into a triage workspace instead of a simple imported-results list.

### Filtering

- category
- priority
- severity
- state
- source
- asset criticality

### Core visible fields

- title
- affected asset
- category
- priority
- severity
- confidence
- state
- first seen
- last seen

### UX improvements

- expandable evidence panel
- remediation panel with recommended action
- bulk actions:
  - resolve
  - accepted risk
  - false positive
  - assign owner
  - add note
  - suppress

### Additional workflow views

- new since last scan
- recently changed
- stale unresolved

## Phase 5: Promote AI Observations into First-Class Findings

Today AI observations are mostly stranded on the asset page. Those should become part of the same finding workflow.

### Goal

Map AI `security_findings` into normalized database findings while preserving AI output as supporting evidence rather than primary truth.

### Rules

- AI should contribute explanation and recommended action
- deterministic rules should remain authoritative when possible
- duplicate findings from AI and imported tools should merge rather than multiply

### Deliverables

- AI-to-finding mapper
- dedupe and merge logic

## Phase 6: Add Suppression and Exception Handling

Homelab and small-network environments need practical noise control.

### Suppression criteria

- subnet
- asset tag
- finding category
- service or port
- source

### Required metadata

- reason
- optional expiration
- author

### Example use cases

- suppress self-signed TLS on lab assets
- suppress printer HTTP admin findings on a trusted printer VLAN

### Deliverables

- suppression rules table
- suppression evaluation in finding generation
- UI in Settings or Findings

## Phase 7: Track Finding Lifecycle and Change

Findings should show whether risk is new, persistent, improved, or resolved.

### Lifecycle states and events

- `new`
- `persisting`
- `worsened`
- `improved`
- `resolved_by_absence`
- `reopened`

### Examples

- SMB port newly exposed: new finding
- management service removed: improved or resolved
- finding disappears across multiple scans: resolved candidate
- asset criticality changes: finding priority may change

### Deliverables

- finding event history
- timeline on finding detail
- change-focused dashboard widgets

## Phase 8: Improve Dashboard Visibility

The dashboard should answer:

- what changed since the last scan
- what is newly risky
- what is internet-exposed
- what is weakly managed
- what needs action first

### Suggested widgets

- open findings by priority
- newly introduced high-risk items
- exposed management services
- risky protocols in use
- unresolved findings by asset criticality
- unknown or unclassified devices with high exposure

## Suggested Milestones

### Milestone 1: Foundation

- expand `Finding` schema
- update API and frontend types

### Milestone 2: Rule-Driven Findings

- implement initial rule engine
- add first 10 to 12 findings rules
- add backend test coverage

### Milestone 3: Findings UI v2

- redesign Findings page
- add priority, category, confidence, evidence, and bulk triage

### Milestone 4: Context-Aware Prioritization

- asset criticality and environment
- smarter priority calculation

### Milestone 5: AI Merge and Suppression

- promote AI observations into findings
- add suppression and accepted-risk workflows

### Milestone 6: Lifecycle and Trend Reporting

- finding history
- change tracking
- richer dashboard summaries

## Recommended First Sprint

If this roadmap is resumed later, the highest-value first sprint would be:

1. Expand the `Finding` model
2. Add a rule engine
3. Implement six core rules:
   - Telnet
   - FTP
   - SNMP v2
   - HTTP admin
   - exposed SSH or RDP
   - UPnP on gateway
4. Redesign Findings for category, priority, and state
5. Add bulk resolve and accepted-risk actions

## Testing Strategy

To avoid coverage regression:

- backend unit tests for each rule
- tests for finding dedupe and merge
- tests for suppression logic
- tests for priority calculation
- route tests for filter and bulk-update endpoints
- frontend type-check coverage and focused component behavior tests

## Shelving Note

This roadmap is intentionally deferred while topology and network diagramming are prioritized. When topology work resumes, Findings should remain a downstream consumer of topology context:

- router and gateway relationships should inform exposure scoring
- uplink and segment placement should improve priority calculation
- topology awareness should eventually help detect management-plane exposure and unusual lateral visibility
