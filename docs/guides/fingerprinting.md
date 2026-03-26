---
id: fingerprinting
title: Fingerprinting Guide
sidebar_position: 15
---

# Fingerprinting Guide

Argus uses a layered, evidence-driven approach to classify devices. Rather than relying on a single signal, it collects evidence from multiple sources, assigns confidence weights to each, and synthesizes them into a device classification. Optional AI synthesis can then reason across all collected evidence to refine the result.

## How Fingerprinting Works

Fingerprinting happens across multiple pipeline stages and produces a classification with an associated confidence score. The goal is hypothesis generation, not authoritative fact extraction — Argus is explicit about uncertainty when evidence is ambiguous.

### Stage 3: Heuristic Classification

After port scanning, heuristic rules run against each host. Inputs include:

- **MAC OUI/vendor** — the organizationally unique identifier from the MAC address, looked up against the IEEE OUI database
- **Nmap service banners** — version strings reported by running services
- **Nmap OS fingerprint** — nmap's OS detection result (available in `balanced` and `deep_enrichment` profiles)
- **TTL hint** — the initial TTL value can suggest OS family (≤70 → Linux-like, ≤138 → Windows-like, ≤255 → network appliance)
- **Open port signatures** — certain port combinations strongly suggest device categories (port 445 + 139 → Windows/Samba; port 161 → SNMP-capable appliance)

The heuristic classifier also runs signature matching against known product strings in service banners. Examples of recognized signatures:

| String in Banner | Classified As | Confidence |
|---|---|---|
| `synology` / `diskstation` | NAS | 0.90 |
| `truenas` | NAS | 0.92 |
| `pfsense` / `opnsense` | Firewall | 0.92 |
| `routeros` / `mikrotik` | Router | 0.88 |
| `unifi` / `omada` | Access Point | 0.84–0.86 |
| `playstation` / `ps5` | Game Console | 0.94 |
| `xbox` | Game Console | 0.90 |
| `hikvision` / `dahua` | IP Camera | 0.85 |
| `home assistant` | IoT Device | 0.84 |

### Stage 4: Deep Probes

Deep probes gather direct protocol evidence that the heuristic classifier cannot reach from scan data alone. Probes run concurrently per host and are prioritized based on which ports are open and the current hypothesis.

| Probe | Port(s) | Evidence Gathered |
|---|---|---|
| HTTP | 80, 8080, 8000, etc. | Page title, `Server` header, product strings |
| TLS | 443, 8443, etc. | Certificate CN, Organization, issuer |
| SSH | 22 | Banner string (reveals OS, sometimes hardware model) |
| SNMP | 161 | `sysDescr`, `sysName` — often the single richest source of device identity |
| mDNS | 5353 | Service names, hostname — common for Apple, IoT, and consumer devices |
| UPnP | 1900 | Device XML with make and model |
| SMB | 445, 139 | Windows version, Samba details |

The AI agent (Stage 5) uses probe results as its primary reasoning material, so running deep probes significantly improves AI classification quality.

:::tip When Probes Are Skipped
The `quick` profile disables deep probes entirely. The `balanced` and `deep_enrichment` profiles enable them. The probe timeout is configurable in Settings (default: 6 seconds per probe round).
:::

### Stage 5: AI Analysis

When AI analysis is enabled, an AI agent receives all collected evidence and reasons to a structured conclusion. The agent is told to treat this as hypothesis generation — it must prefer "unknown" over overclaiming.

The AI analysis produces:

- `device_class` — one of the supported device types (router, switch, server, workstation, NAS, printer, etc.)
- `vendor` — inferred vendor name
- `confidence` — a 0–1 score for how certain the classification is
- `investigation_notes` — the agent's reasoning and any caveats
- `security_findings` — notable security observations (open Telnet, SMBv1, weak TLS, default SNMP community, etc.)

#### AI Backends

The AI backend used for Stage 5 investigation is configured in **Settings → Discovery Engine → AI Analysis**.

| Backend | Setting Value | Notes |
|---|---|---|
| Ollama (local) | `ollama` | Default; requires a running Ollama instance |
| OpenAI-compatible | `openai` | Any OpenAI API-compatible endpoint |
| Anthropic | `anthropic` | Requires an Anthropic API key |

For Ollama, you must also specify the model name (e.g., `llama3`, `mistral`). The Settings page can fetch the list of available models from your Ollama instance.

#### Fingerprint AI (Post-Scan Synthesis)

Separate from the per-host AI agent, there is also a **fingerprint AI** that can synthesize persisted evidence for already-discovered assets. This runs as a post-scan enrichment step and uses the same configurable backend.

The fingerprint AI is useful for improving classifications on assets discovered in quick scans, or for re-analyzing assets after new evidence is collected.

## Evidence Items

Each piece of collected data is stored as an **evidence item** with:

- `source` — where the evidence came from (e.g., `nmap`, `http_probe`, `snmp_probe`, `mac_oui`)
- `category` — what the evidence relates to (e.g., `device_type`, `vendor`, `os_guess`)
- `key` — the specific attribute
- `value` — the observed value
- `confidence` — a 0–1 score for how strongly this evidence supports the claim

The asset detail page in the UI displays collected evidence items so you can inspect what was found and how confident each piece is.

## Autopsy Traces

An **autopsy trace** is a structured record of the reasoning process Argus followed to reach its classification. It is stored per-asset and is visible on the asset detail page under the Autopsy tab.

The autopsy trace captures:

- which evidence was considered
- which heuristic rules fired
- what classification each stage produced
- where evidence was absent, weak, or contradictory

This is the primary tool for diagnosing classification errors. If Argus classifies a device incorrectly, the autopsy trace shows exactly why.

## Internet Lookup

Argus supports an optional, allowlisted internet lookup for MAC OUI resolution and vendor identification when local datasets do not have a match.

This is disabled by default. When enabled, the budget and allowed domain list limit what can be looked up.

Configure in **Settings → Discovery Engine → Internet Lookup**:

- `enabled` — master switch
- `allowed_domains` — comma-separated list of permitted lookup domains
- `budget` — maximum number of external requests per scan
- `timeout_seconds` — per-request timeout

:::caution Privacy
Internet lookups for MAC addresses can expose your network device inventory to external services. Only enable this if you understand and accept that tradeoff.
:::

## Device Classes

Argus classifies devices into the following types:

| Class | Description |
|---|---|
| `router` | Layer 3 routing device |
| `switch` | Layer 2 switching device |
| `access_point` | Wireless access point or mesh node |
| `firewall` | Dedicated firewall or security gateway |
| `server` | General-purpose server (includes NVR, media servers) |
| `workstation` | Desktop, laptop, or general-purpose compute |
| `nas` | Network-attached storage |
| `printer` | Network printer |
| `ip_camera` | IP camera or NVR |
| `smart_tv` | Smart TV or streaming device |
| `game_console` | Gaming console (PlayStation, Xbox, Nintendo Switch) |
| `iot_device` | IoT or smart home device |
| `voip` | VoIP phone or adapter |
| `unknown` | Insufficient evidence to classify |

## Confidence Interpretation

| Range | Meaning |
|---|---|
| 0.90 – 1.00 | High confidence — direct identification from a strong single source (e.g., SNMP sysDescr, TLS certificate) |
| 0.70 – 0.89 | Moderate confidence — consistent evidence from 2–3 sources |
| 0.50 – 0.69 | Low confidence — some evidence but ambiguous or single-source |
| 0.00 – 0.49 | Very low confidence — limited evidence; classification should be treated as a guess |

When the AI agent reports confidence below the configured minimum (`fingerprint_ai_min_confidence`), the result is not automatically applied to the asset classification.

## Related Docs

- [Scanner Guide](./scanner.md)
- [Scan Profiles](./scan-profiles.md)
- [Settings Reference](./settings-reference.md)
- [Troubleshooting](../troubleshooting.md)
