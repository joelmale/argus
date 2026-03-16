"""
DNS Enrichment

Reverse DNS lookup: given an IP, find its PTR record hostname.
Forward confirmation: resolve the found hostname back to an IP to validate.

Many home lab devices have meaningful PTR records set by the router's
DHCP/DNS integration (e.g. "proxmox.local", "nas.home", "pi.hole").
"""
from __future__ import annotations

import asyncio
import logging
import socket

log = logging.getLogger(__name__)


async def reverse_lookup(ip: str, timeout: float = 3.0) -> str | None:
    """Return PTR hostname for an IP, or None if not found."""
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            timeout=timeout,
        )
        hostname = result[0]
        # Filter out meaningless results like the IP itself or generic placeholders
        if hostname == ip or hostname.startswith("broadcasthost"):
            return None
        return hostname
    except (socket.herror, socket.gaierror):
        return None
    except asyncio.TimeoutError:
        return None
    except Exception as exc:
        log.debug("Reverse DNS error for %s: %s", ip, exc)
        return None


async def forward_lookup(hostname: str, timeout: float = 3.0) -> list[str]:
    """Return list of IPs for a hostname."""
    loop = asyncio.get_event_loop()
    try:
        results = await asyncio.wait_for(
            loop.run_in_executor(None, socket.getaddrinfo, hostname, None),
            timeout=timeout,
        )
        return list({r[4][0] for r in results})
    except Exception:
        return []
