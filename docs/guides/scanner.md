---
id: scanner-guide
title: Scanner Guide
sidebar_position: 10
---

# Scanner Guide

`argus-scanner` is responsible for active discovery, passive observation, and selected external log ingestion workflows.

## Core Responsibilities

- target resolution
- host discovery
- port scanning
- deeper protocol investigation
- passive ARP observation
- DHCP/DNS-style log ingestion support
- scheduled scan execution
- scan progress reporting

## Pipeline Stages

Argus processes every scan through six sequential stages. Each stage feeds the next, and live progress events are emitted throughout so the UI and any WebSocket listener can follow the scan in real time.

| Stage | Name | What Happens |
|---|---|---|
| 1 | Discovery | ARP and ping sweep to find live hosts on the target subnet |
| 2 | Port Scan | nmap enumerates open ports, services, and OS fingerprints across all discovered hosts |
| 3 | Fingerprint | Heuristic rules classify each host based on MAC vendor, service banners, port signatures, and TTL hints |
| 4 | Deep Probes | Targeted protocol probes (HTTP, TLS, SSH, SNMP, mDNS, UPnP, SMB) collect richer evidence per host |
| 5 | AI Analysis | Optional AI agent synthesizes all collected evidence into a structured device classification |
| 6 | Persist | Results are upserted into the database; offline reconciliation runs; WebSocket events are emitted |

:::info Stage Control
Stages 3–5 run concurrently across hosts (limited by the `concurrent_hosts` setting). This means a /24 with 50 live hosts and `concurrent_hosts=10` runs approximately five batches of ten hosts in parallel.
:::

Argus also stores an asset **autopsy trace** so an operator can inspect exactly how a classification was reached and where the evidence was weak or absent.

:::tip Partial Scans
If a scan is cancelled or paused during Stage 6, Argus can preserve discovery-only results — assets appear in inventory with minimal data and are enriched on the next full scan.
:::

## Discovery and Port Scan Behavior

The scanner uses `nmap` for:

- host discovery
- service detection
- OS fingerprinting

Important implementation behavior:

- once a host is already discovered, Argus forces `-Pn` for port scans
- this avoids false “host seems down” behavior from a second host-discovery pass

## Fingerprinting Inputs

Scanner-side and enrichment-side inputs include:

- MAC address and vendor mapping
- Nmap service banners
- SSH banners
- TLS certificate details
- HTTP headers and titles
- SNMP metadata
- passive observations
- imported or module-specific client/log data

## Beacon Reporting and Wireless Signals

Argus can ingest and analyze log-derived wireless events from supported modules such as the TP-Link Deco integration.

Examples of log patterns Argus can now interpret:

- band steering mismatches
- 802.11k timeouts
- repeated threshold recalculation
- invalid controller message length
- client association activity
- weak or dead-zone datarate conditions

These are turned into:

- structured issues
- operator-facing recommendations
- simple health scoring

## Log Parsing Logic

Argus uses rule-based parsing for recurring patterns in external log feeds.

Typical recommendation workflow:

- match patterns with regex
- group repeated events
- extract MAC addresses when present
- assign severity and health penalties
- emit operator guidance

Example outcome categories:

| Pattern Type | Likely Interpretation |
|---|---|
| `targetBand != measuredBss->band` | aggressive band steering mismatch |
| `Timeout waiting for 802.11k response` | roaming capability or coverage issue |
| `patrate ... is 0` | dead zone, weak path, or interference |
| `Beacon report ... unexpected state` | protocol mismatch or unstable client behavior |

## Passive Observation

Passive observation is intended to complement active scans, not replace them.

Current passive and imported signals include:

- ARP observations
- DHCP/DNS-style log ingestion
- module-fed observations from integrations

Passive events help with:

- transient devices
- first seen / last seen timelines
- hostname hints
- MAC/IP correlation

## Scanner Settings

Relevant Settings UI controls include:

- enable scheduled scans
- default targets
- auto-detect local subnet
- default profile
- interval
- concurrent hosts
- passive ARP enablement
- passive interface selection
- SNMP version and credentials

## Operational Notes

### Docker Desktop for Mac

The scanner depends on Docker being healthy and, in development, on host-network access. If builds or container inspection calls begin failing with Docker `500` errors, verify the `desktop-linux` context and restart Docker Desktop before debugging Argus itself.

### Subnet Accuracy

If discovery counts are implausibly high:

- verify the effective target range in Settings
- confirm the scanner is not using a stale bootstrap subnet
- confirm host discovery is only counting responsive hosts

### Scan Visibility

The scan management page exposes:

- current stage
- progress message
- discovered host count
- investigated host count
- expandable active-scan detail view

## Related Docs

- [Architecture](../architecture.md)
- [Scan Profiles](./scan-profiles.md)
- [Fingerprinting Guide](./fingerprinting.md)
- [Settings Reference](./settings-reference.md)
- [Troubleshooting](../troubleshooting.md)
