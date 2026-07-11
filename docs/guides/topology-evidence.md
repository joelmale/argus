---
id: topology-evidence
title: Topology Evidence and Correction
sidebar_position: 18
---

# Topology Evidence and Correction

Argus topology is evidence-first. A link in the topology graph should not be
treated as a bare line between two devices. It should answer why the relationship
exists, how strong the evidence is, and whether an operator corrected it.

## Relationship Kinds

| Kind | Meaning |
|---|---|
| Observed | A concrete source reported the relationship, such as SNMP, UniFi, Deco, wireless association data, or controller data. |
| Inferred | Argus derived the relationship from weaker signals such as segment membership, gateway scoring, AP tags, or heuristic role inference. |
| Manual | An operator confirmed, created, or corrected the relationship. |

## Edge Evidence

Selecting an edge in the topology graph shows:

- relationship type
- observed, inferred, or manual state
- confidence
- source
- last seen time
- interface or SSID metadata where available
- explanation
- raw evidence payload

Low-confidence inferred edges are work items. Confirm them when they are correct.
Suppress them when they are wrong.

## Node Evidence

Selecting a node shows:

- asset identity
- inferred or manually overridden topology role
- segment
- status
- confidence
- latency and TTL hints
- vendor and OS hints

Admins can set a topology role override when Argus has the wrong role. The
override is stored with the asset and is used when rebuilding the graph.

## Correction Actions

| Action | Effect |
|---|---|
| Confirm inferred link | Creates or updates a durable manual link with high confidence. |
| Suppress link | Hides the relationship and prevents the same inferred link from being regenerated. |
| Create manual link | Adds an operator-defined relationship between two selected nodes. |
| Delete manual link | Removes an operator-created relationship. |
| Set role override | Stores the preferred topology role on the asset. |
| Clear role override | Returns the asset to inferred role behavior. |

Manual corrections are audit logged. Manual links and role overrides should be
preferred over weaker inference until the operator clears them.

## Related Docs

- [Topology Engineering Plan](./topology-engineering-plan.md)
- [Operator Experience Plan](./operator-experience-plan.md)
- [Daily Use Guide](./daily-use.md)
