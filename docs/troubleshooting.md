---
id: troubleshooting
title: Troubleshooting
sidebar_position: 20
---

# Troubleshooting

This guide collects common failure modes seen during development and operation of Argus.

## Docker and Local Runtime

### Docker Desktop returns `500 Internal Server Error`

Symptoms:

- `docker compose` fails while inspecting or building images
- image JSON lookup fails
- build hangs around manifest export or image inspection

Typical cause:

- Docker Desktop on Mac is unhealthy
- wrong or stale Docker context

Checks:

```bash
docker context ls
docker context use desktop-linux
docker version
docker ps
```

If Docker commands hang or fail, restart Docker Desktop.

:::tip
When the stack is already running, prefer `npm run dev:ps` or `npm run dev:logs` instead of rebuilding immediately. This reduces unnecessary interaction with the Docker image API.
:::

## Login Issues

### Login says “incorrect username or password”

Possible causes:

- real credential mismatch
- backend is reachable but rejecting auth
- frontend cannot reach backend

Checks:

```bash
curl http://localhost:8000/health
```

Look in the browser console:

- `401 Unauthorized` usually means real auth rejection
- network failure or CORS failure points to backend reachability or server errors

## Asset Detail Fails to Load

Symptoms:

- asset detail says “asset not found”
- browser console shows request failures for `/api/v1/assets/{id}`

Checks:

- confirm backend is healthy
- inspect backend logs for serializer or database errors
- refresh after backend restart if the stack was hot-reloaded during a schema or relationship change

## Scanner and Discovery

### Host count is impossibly high

Symptoms:

- scan UI shows a `/20` resolving to thousands of discovered hosts

Checks:

- verify effective targets in Settings
- confirm discovery is only counting responsive hosts
- clear stale inventory if an early bad scan polluted the dataset

### Ports show as closed or absent when `nmap -Pn` finds them

Cause:

- the host responds to direct TCP probes but not to the default nmap host-discovery pass

Argus behavior:

- discovered hosts are now port scanned with `-Pn`

If you still see a mismatch:

- verify the asset was rediscovered after the fix
- compare the asset’s open-port panel with a direct `nmap -Pn` run

### Wrong subnet is being scanned

Checks:

- review scanner settings in the UI
- confirm `effective target`
- clear old inventory if a stale bootstrap subnet was scanned first

## Deco and Wireless Log Patterns

### `targetBand(X) != measuredBss->band(Y)`

Meaning:

- aggressive or failed band steering

Likely operator action:

- reduce steering aggressiveness
- separate 2.4 GHz and 5 GHz SSIDs for testing

### `Timeout waiting for 802.11k response`

Meaning:

- a client did not answer roaming measurements

Likely operator action:

- check client firmware
- verify signal strength and AP placement
- reduce roaming aggressiveness for marginal clients

### `estimated pat datarate is 0`

Meaning:

- likely dead zone, poor backhaul, or severe interference

Likely operator action:

- move the node
- reduce interference
- review mesh placement

### `Beacon report ... unexpected state`

Meaning:

- client protocol mismatch or unstable roaming interaction

Likely operator action:

- reconnect the client
- update firmware
- disable fast roaming for that device if repeated

### `Invalid message len`

Meaning:

- malformed or inconsistent controller messaging in the mesh system

Likely operator action:

- reboot the affected node
- check firmware consistency across mesh nodes

## Deco Module Problems

### Test connection or sync fails

Checks:

- verify the local portal URL
- verify the owner password
- confirm the module is enabled
- confirm the Deco portal is reachable from the Argus host

Notes:

- the local Deco login screen only asks for a password, but request signing still uses a hidden `admin` username
- Argus handles that internally

### System-log export does not match TP-Link “Save to Local”

Argus behavior:

- Argus uses the live paged system-log feed as the authoritative source
- it assembles its own downloadable log copy from that feed

This is more reliable than depending on the vendor’s local-export wrapper.

## SNMP and Passive Discovery

### SNMP is configured but no useful data appears

Checks:

- verify SNMP version and credentials in Settings
- verify the target device actually exposes the desired OIDs
- confirm timeout is not too low

For consumer gear, limited SNMP support is common.

### Passive ARP is not producing observations

Checks:

- verify passive ARP is enabled
- verify the configured interface is correct
- confirm the scanner is running with host-network access in development

## Frontend Development Indicators

### Next.js icon appears in the lower-left corner

That is the Next.js development indicator, not an Argus UI element. It appears in dev mode and does not ship in a production build.

## Recommended Debug Order

1. confirm Docker health
2. confirm backend health endpoint
3. confirm frontend can reach backend
4. confirm scanner effective target range
5. compare Argus behavior with direct tool output such as `nmap -Pn`
6. inspect scan detail, autopsy trace, and evidence panels

## Related Docs

- [Getting Started](./getting-started.md)
- [Scanner Guide](./guides/scanner.md)
