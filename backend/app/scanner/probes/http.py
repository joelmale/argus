"""
HTTP/HTTPS Probe

Fetches response headers, page title, server banner, and a body snippet.
The body snippet is intentionally limited (500 chars) — just enough for
the AI agent to identify the application (Proxmox login, Synology DSM,
pfSense, Home Assistant, Nginx default page, etc.) without wasting tokens.

Also probes a handful of common admin paths to detect known applications.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
from urllib.parse import urlparse

import httpx

from app.scanner.models import HttpProbeData, ProbeResult

log = logging.getLogger(__name__)

# Common admin/login paths to check — each one may uniquely fingerprint an app
INTERESTING_PATHS = [
    "/",
    "/admin", "/admin/", "/manager/", "/panel/",
    "/cgi-bin/", "/cgi-bin/luci",               # OpenWRT
    "/webman/index.cgi",                          # Synology DSM
    "/ui/",                                       # Unifi
    "/system/console",                            # Proxmox
    "/ng/",                                       # pfSense/OPNsense
    "/hassio/", "/lovelace/",                     # Home Assistant
    "/index.php", "/login.php",
    "/.well-known/",
    "/api/", "/api/v1/", "/swagger/", "/docs/",   # API endpoints
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


async def probe(ip: str, port: int, use_https: bool = False, timeout: float = 5.0) -> ProbeResult:
    """Run HTTP probe against ip:port. Returns ProbeResult with HttpProbeData in .data."""
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{ip}:{port}"
    t0 = time.monotonic()

    data = HttpProbeData(url=base_url)
    raw_parts: list[str] = []

    try:
        async with httpx.AsyncClient(
            verify=False,           # Self-signed certs are common on LAN devices
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Argus/1.0; network-scanner)"},
        ) as client:
            # ── Main request ──────────────────────────────────────────────
            resp = await client.get(base_url + "/")
            data.status_code = resp.status_code
            data.content_type = resp.headers.get("content-type")
            data.server = resp.headers.get("server")
            data.powered_by = resp.headers.get("x-powered-by")
            data.auth_header = resp.headers.get("www-authenticate")
            data.auth_required = resp.status_code in (401, 403)
            data.redirects = [str(r.url) for r in resp.history]
            data.headers = dict(resp.headers)
            if resp.history:
                final_host = urlparse(str(resp.url)).hostname
                if final_host and final_host != ip:
                    data.redirect_host = final_host

            body = resp.text[:2000]
            raw_parts.append(f"GET / -> {resp.status_code}\n{resp.headers}\n\n{body[:500]}")

            # Extract title
            m = TITLE_RE.search(body)
            if m:
                data.title = m.group(1).strip()[:200]

            # Body snippet for AI
            data.body_snippet = body[:500]
            data.detected_app = _detect_app(data.server, data.powered_by, data.auth_header, data.title, body)

            favicon_hash = await _fetch_favicon_hash(client, base_url)
            if favicon_hash:
                data.favicon_hash = favicon_hash

            # ── Probe interesting paths (non-root only) ───────────────────
            found_paths: list[str] = []
            path_tasks = [
                _probe_path(client, base_url, path)
                for path in INTERESTING_PATHS[1:]          # skip "/" already done
            ]
            path_results = await asyncio.gather(*path_tasks, return_exceptions=True)
            for path, result in zip(INTERESTING_PATHS[1:], path_results):
                if isinstance(result, int) and result not in (404, 400, 0):
                    found_paths.append(f"{path} ({result})")
            data.interesting_paths = found_paths

    except httpx.ConnectError:
        return ProbeResult(probe_type="http", target_port=port, success=False, error="Connection refused")
    except httpx.TimeoutException:
        return ProbeResult(probe_type="http", target_port=port, success=False, error="Timeout")
    except Exception as exc:
        return ProbeResult(probe_type="http", target_port=port, success=False, error=str(exc)[:200])

    return ProbeResult(
        probe_type="https" if use_https else "http",
        target_port=port,
        success=True,
        duration_ms=round((time.monotonic() - t0) * 1000, 1),
        data=data.model_dump(),
        raw="\n".join(raw_parts),
    )


async def _probe_path(client: httpx.AsyncClient, base_url: str, path: str) -> int:
    """Return status code for a path, or 0 on error."""
    try:
        r = await client.get(base_url + path, follow_redirects=False)
        return r.status_code
    except Exception:
        return 0


async def _fetch_favicon_hash(client: httpx.AsyncClient, base_url: str) -> str | None:
    try:
        resp = await client.get(base_url + "/favicon.ico", follow_redirects=True)
        if resp.status_code != 200 or not resp.content:
            return None
        content_type = resp.headers.get("content-type", "")
        if not any(token in content_type.lower() for token in ("image", "icon", "octet-stream")):
            return None
        return hashlib.sha256(resp.content).hexdigest()[:16]
    except Exception:
        return None


def _detect_app(
    server: str | None,
    powered_by: str | None,
    auth_header: str | None,
    title: str | None,
    body: str,
) -> str | None:
    haystack = " ".join(
        part for part in (server, powered_by, auth_header, title, body[:1500]) if part
    ).lower()

    signatures = [
        ("proxmox", "Proxmox VE"),
        ("pve", "Proxmox VE"),
        ("home assistant", "Home Assistant"),
        ("synology", "Synology DSM"),
        ("diskstation", "Synology DSM"),
        ("qnap", "QNAP"),
        ("truenas", "TrueNAS"),
        ("freenas", "TrueNAS"),
        ("unifi", "UniFi"),
        ("omada", "TP-Link Omada"),
        ("tplink", "TP-Link"),
        ("tp-link", "TP-Link"),
        ("deco", "TP-Link Deco"),
        ("routeros", "MikroTik RouterOS"),
        ("mikrotik", "MikroTik RouterOS"),
        ("openwrt", "OpenWrt"),
        ("luci", "OpenWrt LuCI"),
        ("pfsense", "pfSense"),
        ("opnsense", "OPNsense"),
        ("jellyfin", "Jellyfin"),
        ("plex", "Plex"),
        ("immich", "Immich"),
        ("frigate", "Frigate"),
        ("grafana", "Grafana"),
        ("prometheus", "Prometheus"),
    ]
    for needle, label in signatures:
        if needle in haystack:
            return label
    return None
