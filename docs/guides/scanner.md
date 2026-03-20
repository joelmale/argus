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

## Discovery Flow

At a high level, Argus processes a scan in stages:

1. resolve effective targets
2. perform discovery
3. run port scans against discovered hosts
4. run deeper probes and fingerprinting
5. persist results
6. emit live status events

Argus also stores an asset autopsy trace so an operator can inspect how a classification was reached and where evidence was weak.

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
- [Troubleshooting](../troubleshooting.md)
