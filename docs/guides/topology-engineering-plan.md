# Topology Engineering Plan

This document turns the topology roadmap into a concrete engineering plan for Argus. It is designed for homelab and prosumer networks, not large enterprise campus or WAN environments.

The goal is to move Argus from a generic asset graph to a useful network map that:

- groups devices by segment
- identifies gateways, switches, access points, and endpoints
- distinguishes observed links from inferred links
- models wireless and mesh relationships
- remains understandable and stable for small-network operators

## Product Scope

This plan intentionally optimizes for:

- home labs
- prosumer routers, switches, and access points
- small self-hosted environments
- mixed wired and wireless networks
- VLANs and guest networks where detectable

This plan does **not** target:

- multi-site WAN modeling
- enterprise path tracing
- SD-WAN, MPLS, EVPN, or campus fabric orchestration
- full packet-level topology discovery

## Design Principles

1. Observed data beats inferred data.
2. Inferred data is still valuable if confidence is explicit.
3. Segment-aware, layered maps are better than generic force graphs for homelabs.
4. Wireless and gateway relationships are disproportionately important in small networks.
5. User-correctable topology is required because consumer gear often exposes incomplete data.

## Current State

Current backend and frontend behavior:

- [topology.py](/Users/JoelN/Coding/argus/backend/app/api/routes/topology.py) returns all assets plus raw `TopologyLink` rows
- [TopologyMap.tsx](/Users/JoelN/Coding/argus/frontend/src/components/topology/TopologyMap.tsx) renders them with a generic Cytoscape force layout
- SNMP already collects:
  - LLDP/CDP neighbors
  - wireless client data
- [topology.py](/Users/JoelN/Coding/argus/backend/app/scanner/topology.py) already persists some inferred or observed links

The main weakness is not absence of any topology data. The weakness is that the system does not yet build a network model from that data.

## Architecture Target

Argus topology should evolve toward these primitives:

- `Segment`
  - subnet or VLAN-like grouping
- `Node`
  - asset plus topology role metadata
- `Relationship`
  - typed edge with confidence and evidence
- `Evidence`
  - LLDP, CDP, wireless association, ARP, module output, manual override
- `Layout Layer`
  - WAN edge, gateway layer, switching/AP layer, endpoint layer

## Proposed Relationship Types

- `uplink`
- `gateway_for`
- `switches_for`
- `wireless_ap_for`
- `neighbor_l2`
- `neighbor_l3`
- `same_segment`
- `controller_for`
- `mesh_backhaul`
- `observed_on_interface`
- `arp_seen_by`
- `manual_override`

Each relationship should eventually carry:

- `relationship_type`
- `confidence`
- `observed`
- `source`
- `evidence`
- `last_seen`
- `segment_id`
- `local_interface`
- `remote_interface`
- `ssid`
- `metadata`

## Delivery Strategy

Build topology in layers:

1. data model
2. inference engine
3. API contract
4. frontend layout
5. correction workflow
6. change tracking

Each phase below includes:

- technical goals
- file areas to change
- testing plan
- recommended commit points

## Phase 1: Topology Data Model Foundation

### Goals

- extend the topology schema to support typed, confidence-aware relationships
- introduce first-class segment objects
- keep compatibility with the current graph flow during migration

### Backend changes

1. Add a `network_segments` table.
2. Extend `TopologyLink` in [models.py](/Users/JoelN/Coding/argus/backend/app/db/models.py) with:
   - `relationship_type`
   - `confidence`
   - `observed`
   - `source`
   - `evidence`
   - `last_seen`
   - `segment_id`
   - `local_interface`
   - `remote_interface`
   - `ssid`
   - `metadata`
3. Optionally add topology role fields to `Asset`:
   - `topology_role`
   - `topology_role_confidence`
4. Add Alembic migration.

### API changes

- update [topology.py](/Users/JoelN/Coding/argus/backend/app/api/routes/topology.py) serializers
- keep current `/graph` working but add richer edge and node payloads

### Testing

- migration tests if present in repo workflow
- model serialization tests
- route contract tests for `/api/v1/topology/graph`
- backward compatibility tests for existing frontend expectations

### Coverage target

- do not merge unless route and serializer paths are covered

### Commit points

1. `Add segment and typed topology link schema`
2. `Expose typed topology fields in graph API`
3. `Add topology schema and serializer tests`

## Phase 2: Segment Inference Engine

### Goals

- derive useful network segments from available data
- group assets into subnet or VLAN-like containers
- identify candidate gateway per segment

### Backend changes

Add new modules:

- `backend/app/topology/segments.py`
- `backend/app/topology/scoring.py`

Implement:

1. Segment derivation from:
   - IP subnet
   - VLAN hints where available
   - SSID or guest-network indicators when available
2. Gateway candidate scoring using:
   - existing device classification
   - service patterns
   - DNS/DHCP hints
   - router/firewall vendor fingerprints
3. Segment-to-asset assignment

### Integration points

- post-scan pipeline in [pipeline.py](/Users/JoelN/Coding/argus/backend/app/scanner/pipeline.py)
- config reset logic in [config.py](/Users/JoelN/Coding/argus/backend/app/scanner/config.py)

### Testing

- unit tests for:
  - subnet grouping
  - gateway scoring
  - segment assignment
- fixtures for:
  - flat home subnet
  - IoT VLAN
  - guest WiFi network

### Coverage target

- every segment scoring rule covered by explicit unit tests

### Commit points

1. `Add segment inference primitives`
2. `Infer candidate gateways for homelab segments`
3. `Add segment inference test coverage`

## Phase 3: Relationship Inference Engine

### Goals

- merge hard-observed and soft-inferred relationships into one model
- prioritize observed links
- keep inferred links visible but confidence-scored

### Backend changes

Add module:

- `backend/app/topology/inference.py`

Implement edge builders for:

1. LLDP/CDP neighbor relationships
2. wireless AP-to-client relationships
3. controller-to-managed-device relationships
4. gateway-to-segment relationships
5. switch/AP-to-endpoint probable parent relationships
6. ARP-based low-confidence adjacency

### Rules

- observed wireless association -> `wireless_ap_for`, high confidence
- LLDP/CDP -> `neighbor_l2`, high confidence
- router/firewall + segment ownership -> `gateway_for`, medium/high confidence
- endpoint in same segment with no better parent -> inferred `uplink`, low/medium confidence

### Testing

- unit tests per relationship rule
- dedupe tests when multiple data sources describe the same link
- confidence ordering tests

### Coverage target

- rule engine must be fully unit tested
- no relationship type added without a test fixture

### Commit points

1. `Add observed topology relationship builders`
2. `Add inferred uplink and gateway relationship builders`
3. `Deduplicate and score topology relationships`
4. `Add topology inference unit tests`

## Phase 4: Graph Builder and API v2

### Goals

- expose a graph payload that represents a network, not just arbitrary nodes and edges
- include segments and layout hints

### Backend changes

Add module:

- `backend/app/topology/graph_builder.py`

Graph payload should include:

- `segments`
- `nodes`
- `edges`
- layout hints:
  - `tier`
  - `segment_id`
  - `is_gateway`
  - `is_infrastructure`
  - `is_observed`

### Node hints

- `internet_edge`
- `gateway`
- `switch`
- `access_point`
- `controller`
- `endpoint`

### Edge hints

- `relationship_type`
- `observed`
- `confidence`
- `segment_id`
- `source_kind`

### API changes

- evolve [topology.py](/Users/JoelN/Coding/argus/backend/app/api/routes/topology.py)
- preserve current route but enrich payload rather than inventing a second public endpoint unless necessary

### Testing

- API response structure tests
- snapshot-style graph fixture tests
- serializer tests for segment-aware payloads

### Coverage target

- payload builder code fully exercised by fixtures

### Commit points

1. `Add segment-aware topology graph builder`
2. `Expose layout hints and confidence in topology API`
3. `Add graph builder fixture coverage`

## Phase 5: Frontend Topology UI Redesign

### Goals

- replace the “dots in a row” feel with a layered network map
- make observed vs inferred relationships obvious
- support segment-aware views

### Frontend changes

Primary file:

- [TopologyMap.tsx](/Users/JoelN/Coding/argus/frontend/src/components/topology/TopologyMap.tsx)

Supporting files:

- [index.ts](/Users/JoelN/Coding/argus/frontend/src/types/index.ts)
- [useAssets.ts](/Users/JoelN/Coding/argus/frontend/src/hooks/useAssets.ts)
- possibly new topology-specific UI components

### UI modes

1. `Overview`
   - WAN / gateway / infra / endpoints
   - grouped by segment
2. `Segment view`
   - one segment at a time
3. `Wireless view`
   - APs and clients emphasized
4. `Raw graph`
   - optional advanced mode for debugging

### Visual conventions

- solid edges = observed
- dashed edges = inferred
- node shape by role
- color by device type
- badges for:
  - gateway
  - AP
  - switch
  - controller
- segment containers or lane-based grouping

### Interactions

- filter by segment
- filter by relationship type
- show observed only
- hide endpoints
- click edge to inspect evidence and confidence
- click node to inspect asset

### Testing

- frontend type-check
- lint
- component behavior tests if available
- manual screenshot verification across:
  - small flat subnet
  - mixed wired/wireless homelab
  - multi-segment lab

### Coverage target

- at minimum, maintain TS and route coverage
- add focused component tests if the frontend test harness is present

### Commit points

1. `Add topology graph types and layout hints to frontend`
2. `Render observed vs inferred edges in topology view`
3. `Add segment-aware topology layout`
4. `Add topology filters and relationship inspection`

## Phase 6: Manual Correction and Overrides

### Goals

- let users fix bad inference
- persist manual knowledge across rescans

### Features

- mark asset as gateway
- mark asset as switch or AP
- assign asset to segment
- create manual link
- remove bad inferred link
- promote inferred link to trusted manual link

### Backend changes

- extend topology link source handling to include manual overrides
- add override persistence if separate tables are needed

### Frontend changes

- topology side panel or edit controls
- asset-page topology override hooks if useful

### Testing

- route tests for manual override creation/removal
- conflict resolution tests between observed, inferred, and manual links

### Coverage target

- all manual override endpoints covered

### Commit points

1. `Add manual topology override model and API`
2. `Support manual correction from topology UI`
3. `Add override conflict-resolution tests`

## Phase 7: Topology Change Tracking

### Goals

- help users understand what changed between scans
- improve operational usefulness

### Change events to track

- new device
- removed device
- new link
- removed link
- gateway changed
- asset moved segment
- wireless client changed AP
- topology confidence dropped

### Backend changes

- topology diffing service
- optional topology history table

### Frontend changes

- change badges in topology view
- recent topology changes panel on dashboard or topology page

### Testing

- diff engine tests
- event generation tests
- frontend rendering tests for changed edges/nodes

### Coverage target

- diff engine fully unit tested

### Commit points

1. `Add topology diff engine`
2. `Record topology changes between scans`
3. `Show recent topology changes in UI`

## Phase 8: Homelab-Optimized Integrations

### Goals

- improve topology quality using prosumer integrations rather than enterprise-only assumptions

### High-value integrations

- TP-Link Deco
- UniFi
- Omada
- Home Assistant network context
- Proxmox node/bridge context

### Use cases

- controller-managed AP/switch relationships
- mesh backhaul
- SSID-to-AP grouping
- bridge and virtual-host relationships in homelab virtualization

### Testing

- mock integration payload tests
- adapter tests for each supported module

### Commit points

1. `Add controller-aware topology adapters`
2. `Model mesh and managed AP relationships`
3. `Add prosumer topology adapter tests`

## Cross-Phase Testing Plan

To keep code coverage high while this system evolves:

### Backend

- require unit tests for each inference rule
- require fixture-driven graph-builder tests
- add route tests for every topology API extension
- test migrations where feasible
- test reset/cleanup behavior so topology state does not drift

### Frontend

- maintain `eslint` and `npm run type-check`
- add component tests for:
  - edge styling logic
  - segment filters
  - observed vs inferred toggles
  - layout mode controls

### Recommended fixture sets

1. Flat home network
   - one gateway
   - one AP/router combo
   - mixed endpoints
2. Prosumer segmented network
   - gateway
   - managed switch
   - AP
   - IoT VLAN
   - Guest WiFi
3. Mesh network
   - controller
   - multiple nodes
   - wireless clients
4. Virtualized homelab
   - Proxmox
   - bridge-hosted services
   - NAS
   - AP

## Recommended Execution Order

If implementation starts now, the best order is:

1. Phase 1
2. Phase 2
3. Phase 3
4. Phase 4
5. Phase 5
6. Phase 6
7. Phase 7
8. Phase 8

This keeps the sequence logical:

- model the data first
- infer relationships second
- expose richer graph data third
- redesign the UI after the data model is real

## Suggested Milestone Bundles

### Milestone A: Foundational Topology Model

Includes:

- Phase 1
- Phase 2

Outcome:

- segments exist
- candidate gateways exist
- topology data is no longer flat

### Milestone B: Useful Network Map

Includes:

- Phase 3
- Phase 4
- early Phase 5

Outcome:

- network graph reflects relationships
- observed vs inferred edges are visible
- segment-aware layouts work

### Milestone C: Operator-Grade Topology

Includes:

- rest of Phase 5
- Phase 6
- Phase 7

Outcome:

- users can correct the map
- changes between scans are visible
- topology becomes operationally actionable

### Milestone D: Prosumer Integration Quality

Includes:

- Phase 8

Outcome:

- topology quality improves on real homelab gear

## Recommended First Sprint

The highest-value first sprint is:

1. Extend topology schema with typed edges and confidence
2. Add segment derivation from IP subnet
3. Add gateway candidate inference
4. Elevate LLDP/CDP and wireless associations into typed relationships
5. Update frontend graph rendering to distinguish observed vs inferred edges

That will produce the first meaningful jump from “asset dots” to “network map”.

## Practical Commit Plan

Below is a clean commit sequence for implementation:

1. `Add segment and typed topology link schema`
2. `Expose typed topology metadata in graph API`
3. `Add segment inference and gateway scoring`
4. `Infer observed and inferred topology relationships`
5. `Add topology graph builder with layout hints`
6. `Render observed vs inferred topology edges`
7. `Add segment-aware topology layout and filters`
8. `Add manual topology overrides`
9. `Track topology changes between scans`
10. `Add prosumer controller and mesh topology adapters`

Recommended test-focused commits interleaved:

1. `Add topology schema and route coverage`
2. `Add topology inference fixture coverage`
3. `Add graph builder and layout test fixtures`
4. `Add topology override and diff coverage`

## Shelving Note

This plan is intended to be actionable later without rethinking the system from scratch. It deliberately stays focused on the networking patterns that matter in home labs and prosumer environments:

- one or a few gateways
- small managed switching
- AP-driven wireless visibility
- mixed consumer and prosumer devices
- partial observability
- user-correctable inference
