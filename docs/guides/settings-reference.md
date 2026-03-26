---
id: settings-reference
title: Settings Reference
sidebar_position: 16
---

# Settings Reference

The Settings page is the primary way to configure Argus after initial setup. Most settings are persisted in the database and take effect without restarting any service. Settings are organized into four sections.

## Discovery Engine

Controls how the scanner finds and investigates devices.

### Scan Targets

| Setting | Description |
|---|---|
| **Default Targets** | Explicit CIDR ranges or IP addresses to scan (e.g., `192.168.1.0/24`). Comma or space separated. If blank and auto-detect is enabled, the detected subnet is used. |
| **Auto-Detect Local Subnet** | When enabled, the scanner resolves the local subnet from its network interface and uses that as the scan target. This is the recommended mode for single-subnet home labs. |

The **Effective Targets** shown in Settings is the resolved target that will actually be used — this is what gets passed to nmap. Review this before triggering a scan if auto-detect is on.

### Scan Behavior

| Setting | Default | Description |
|---|---|---|
| **Default Profile** | `balanced` | Scan profile used for scheduled and manually triggered scans. See [Scan Profiles](./scan-profiles.md). |
| **Concurrent Hosts** | 10 | Number of hosts investigated in parallel during Stages 3–5. Increase for faster scans on capable hardware; decrease if the network is sensitive. |
| **Host Chunk Size** | 64 | Number of hosts batched into a single nmap port scan call. |
| **Top Ports Count** | 1000 | Number of most common ports to scan (applies to `quick` and `balanced` profiles). Range: 10–65535. |
| **Deep Probe Timeout** | 6 seconds | Per-probe timeout for HTTP, TLS, SSH, SNMP, mDNS, UPnP, and SMB probes. |

### AI Analysis

Controls the AI investigation agent that runs in Stage 5 of the pipeline.

| Setting | Description |
|---|---|
| **AI Backend** | Which AI provider to use: `ollama`, `openai`, or `anthropic`. |
| **Ollama Base URL** | URL of your Ollama instance (e.g., `http://ollama:11434`). |
| **Ollama Model** | Model to use for investigation (e.g., `llama3`, `mistral`). The Settings page can fetch available models from your Ollama instance. |
| **OpenAI Base URL** | Base URL for an OpenAI-compatible API. |
| **OpenAI API Key** | API key for the OpenAI-compatible endpoint. |
| **Anthropic API Key** | API key for the Anthropic API. |
| **AI After Scan Enabled** | Master switch for AI analysis. When off, Stage 5 is skipped entirely for all profiles. |

### Fingerprint AI

The fingerprint AI runs post-scan enrichment using persisted evidence. This is separate from the per-host investigation agent.

| Setting | Description |
|---|---|
| **Fingerprint AI Backend** | Provider for post-scan fingerprint synthesis. Uses same provider options as AI Analysis. |
| **Fingerprint AI Model** | Model name for fingerprint synthesis. |
| **Min Confidence** | Minimum confidence score (0–1) required to apply an AI-generated classification to an asset. Results below this threshold are stored but not automatically applied. |
| **Prompt Suffix** | Optional operator guidance appended to fingerprint prompts (e.g., custom network topology notes or known device patterns in your environment). |

### Internet Lookup

| Setting | Description |
|---|---|
| **Enabled** | Master switch for external lookups during fingerprinting. Disabled by default. |
| **Allowed Domains** | Comma-separated list of domains Argus is permitted to contact for lookups. |
| **Budget** | Maximum number of external lookup requests per scan. |
| **Timeout** | Per-request timeout in seconds. |

### Passive ARP

| Setting | Description |
|---|---|
| **Enabled** | When on, the scanner passively observes ARP traffic on the network interface to record device appearances between active scans. |
| **Interface** | The network interface to listen on (e.g., `eth0`). Defaults to the primary interface. Leave blank to let the scanner choose. |

### SNMP

| Setting | Description |
|---|---|
| **Enabled** | Whether SNMP probes run during deep investigation. |
| **Version** | SNMP version: `v1`, `v2c`, or `v3`. |
| **Community** | Community string for SNMPv1/v2c (e.g., `public`). |
| **Timeout** | SNMP request timeout in seconds. |
| **SNMPv3 Username** | Authentication username for SNMPv3. |
| **SNMPv3 Auth Key** | Authentication passphrase for SNMPv3. |
| **SNMPv3 Priv Key** | Privacy (encryption) passphrase for SNMPv3. |
| **SNMPv3 Auth Protocol** | Authentication protocol: `MD5` or `SHA`. |
| **SNMPv3 Priv Protocol** | Privacy protocol: `DES` or `AES`. |

## Automation

Controls scheduled scanning.

| Setting | Description |
|---|---|
| **Scheduled Scans Enabled** | Master switch for the scheduler. When off, no automatic scans run. |
| **Interval** | How often to run a scheduled scan, in minutes. |
| **Last Scheduled Scan** | Read-only display of when the last scheduled scan ran. |
| **Next Scheduled Scan** | Read-only display of when the next scan is scheduled. |

:::tip Manual Trigger
Enabling scheduled scans does not prevent you from triggering manual scans at any time. A manual scan does not reset the scheduler.
:::

## Access and Control

### Users

Argus has two roles:

| Role | Permissions |
|---|---|
| `admin` | Full access: read, mutate settings, trigger scans, manage users, manage API keys |
| `viewer` | Read-only access to inventory, scans, findings, and topology |

Admins can create and deactivate users from **Settings → Access and Control → Users**.

### API Keys

API keys provide programmatic access without a login session. Keys are created per user and inherit that user's role.

Keys are displayed once at creation. Store them securely — they cannot be retrieved afterward.

To use an API key, pass it as the `X-API-Key` header:

```bash
curl http://localhost:8000/api/v1/assets/ \
  -H 'X-API-Key: <your-key>'
```

## Integrations

### Fingerprint Datasets

Argus uses offline datasets for MAC OUI lookup and other fingerprinting inputs. The datasets panel shows:

- which datasets are loaded
- their last refresh date
- controls to trigger a refresh

Datasets are refreshed on demand, not automatically. Refresh if MAC vendor lookups are returning stale or missing results.

### Backup Policy

Config backup workflows automate SSH-based configuration snapshots for supported network devices. The backup policy settings control:

- which backup drivers are active
- retention and scheduling behavior

### TP-Link Deco

The Deco module connects to the local Deco portal to sync node and client inventory and collect log analysis.

| Setting | Description |
|---|---|
| **Enabled** | Master switch for the Deco module. |
| **Local Portal URL** | URL of the Deco local management portal (e.g., `http://192.168.68.1`). |
| **Owner Password** | The password shown on the Deco app under "Local Manager". The underlying username is `admin` and is handled internally. |

Use **Test Connection** to verify credentials before saving. Use **Sync Now** to trigger an immediate sync outside the scheduled interval.

### Backup Drivers & Plugins

This panel shows installed Argus plugins and their health status. See the [Plugin Development Guide](../plugins/README.md) for how to build and install plugins.

## Applying Settings

Most settings are applied immediately on save. Settings that affect scan behavior (targets, profile, intervals) take effect on the next scan run. The scanner does not need to be restarted.

Settings that affect passive observation (passive ARP interface changes) may require a scanner container restart to re-bind the listener.

## Related Docs

- [Scanner Guide](./scanner.md)
- [Scan Profiles](./scan-profiles.md)
- [Fingerprinting Guide](./fingerprinting.md)
- [Getting Started](../getting-started.md)
