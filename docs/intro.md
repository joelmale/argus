---
id: intro
title: Introduction
sidebar_position: 1
slug: /
---

# Argus

Argus is a self-hosted network management and security platform for home labs and small environments. It combines active discovery, passive observations, asset inventory, topology mapping, fingerprinting, findings ingestion, and operational visibility in one application stack.

The platform is made up of three main services:

- `argus-scanner`: discovery, passive observation, and external log ingestion
- `argus-backend`: API, persistence, orchestration, enrichment, and real-time events
- `argus-frontend`: operator dashboard for assets, scans, findings, topology, and settings

## Value Proposition

Argus is designed to answer a practical set of questions:

- What devices are on my network right now?
- What changed since the last scan?
- What kind of device is this, and how confident is that classification?
- What ports, findings, or lifecycle risks are attached to it?
- What is happening on the network while a scan is running?

Unlike a simple scanner or a static asset list, Argus keeps discovery evidence, change history, live scan state, and operator actions connected in one system.

## Key Capabilities

- Active network discovery with `nmap`
- Passive observations from ARP and imported DHCP/DNS-style logs
- Evidence-driven device fingerprinting
- SNMP-assisted enrichment
- Topology visualization with Cytoscape.js
- Findings ingestion and summary views
- Config backup workflows for supported devices
- Real-time WebSocket event streaming
- JWT auth, role-based access, and API keys
- Optional local AI enrichment with Ollama
- Optional curated internet lookup for unresolved fingerprints

:::tip Homelab First
Argus is intentionally optimized for self-hosted use, Docker-based development, and small-to-medium private environments rather than large enterprise fleet scale.
:::

## Who It Is For

- homelab operators
- security-minded network owners
- small lab or office administrators
- developers building inventory or topology integrations

## Documentation Map

- [Architecture](./architecture.md)
- [Getting Started](./getting-started.md)
- [Scanner Guide](./guides/scanner.md)
- [Backend API Guide](./guides/backend-api.md)
- [Frontend Dashboard Guide](./guides/frontend-dashboard.md)
- [Troubleshooting](./troubleshooting.md)
