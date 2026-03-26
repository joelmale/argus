---
id: scan-profiles
title: Scan Profiles
sidebar_position: 14
---

# Scan Profiles

Argus supports four scan profiles that control nmap arguments, whether deep probes run, and whether AI analysis is enabled. Choosing the right profile is the most direct way to trade off scan speed against discovery depth.

## Profiles at a Glance

| Profile | Speed | Deep Probes | AI Analysis | Best For |
|---|---|---|---|---|
| `quick` | Fastest | No | No | First-pass inventory, routine checks |
| `balanced` | Moderate | Yes | Yes | Default everyday scanning |
| `deep_enrichment` | Slowest | Yes | Yes | Thorough investigation of a subnet |
| `custom` | Varies | Yes | Yes | Callers that supply raw nmap arguments |

## Quick

```text
-sV -T4 --top-ports <count> --host-timeout 20s
```

- Service version detection (`-sV`) but no OS fingerprinting
- Scans the top N ports (default 1000)
- 20-second host timeout
- No deep protocol probes
- No AI analysis

Use `quick` when you want a fast inventory sweep and do not need detailed device classification. It is also the least disruptive profile for sensitive hosts because it skips OS detection scripts.

## Balanced

```text
-sV -O -T4 --top-ports <count> --host-timeout 60s
```

- Service version detection and OS fingerprinting (`-O`)
- Scans the top N ports (default 1000)
- 60-second host timeout
- Deep protocol probes enabled
- AI analysis enabled

`balanced` is the default profile and the recommended starting point for most home labs. It gathers enough evidence for accurate device classification without the full script scan overhead of `deep_enrichment`.

## Deep Enrichment

```text
-A -T4 -p- --osscan-guess --script=default,safe,vuln --host-timeout 90s
```

- All nmap aggressive options: OS detection, version detection, script scanning, and traceroute (`-A`)
- Full port range (`-p-`): all 65535 TCP ports
- OS scan guess enabled for borderline matches
- Default, safe, and vuln script sets
- 90-second host timeout
- Deep protocol probes enabled
- AI analysis enabled

`deep_enrichment` is the most thorough and slowest option. Use it for targeted follow-up scans on a specific subnet or host after a baseline inventory is already established. On a large subnet a full `-p-` scan can take many minutes per host.

:::caution Network Impact
`deep_enrichment` runs the nmap `vuln` script set. Some vulnerability scripts send probe traffic that may trigger IDS alerts or affect sensitive hosts. Review your network's tolerance before running this profile broadly.
:::

## Custom

The `custom` profile instructs the pipeline to accept caller-supplied nmap arguments while still enabling deep probes and AI analysis. It is intended for API clients and automation that have specific scanning requirements not covered by the named profiles.

When no custom nmap arguments are provided, `custom` falls back to `balanced` nmap arguments.

## Configuring the Default Profile

The default profile for scheduled and manually triggered scans is set in **Settings → Discovery Engine → Default Profile**.

You can also override the profile at scan trigger time via the API:

```bash
curl -X POST http://localhost:8000/api/v1/scans/trigger \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"profile": "deep_enrichment"}'
```

## Top Ports Count

All profiles that scan a port range (not `deep_enrichment`) respect the `top_ports_count` setting. The default is 1000. The effective minimum is 10 and the maximum is 65535.

Reducing this number speeds up scans significantly on large subnets. Increasing it above 1000 catches services on less common ports at the cost of scan time.

## Related Docs

- [Scanner Guide](./scanner.md)
- [Settings Reference](./settings-reference.md)
- [Fingerprinting Guide](./fingerprinting.md)
