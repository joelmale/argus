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

DNS_LOOKUP_TIMEOUT_SECONDS = 3.0


async def _await_with_deadline(awaitable, deadline_seconds: float):
    timeout_context = getattr(asyncio, "timeout", None)
    if timeout_context is not None:
        async with timeout_context(deadline_seconds):
            return await awaitable
    return await asyncio.wait_for(awaitable, timeout=deadline_seconds)

async def reverse_lookup(ip: str) -> str | None:
    """Return PTR hostname for an IP, or None if not found."""
    loop = asyncio.get_event_loop()
    try:
        result = await _await_with_deadline(
            loop.run_in_executor(None, socket.gethostbyaddr, ip),
            DNS_LOOKUP_TIMEOUT_SECONDS,
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


async def forward_lookup(hostname: str) -> list[str]:
    """Return list of IPs for a hostname."""
    loop = asyncio.get_event_loop()
    try:
        results = await _await_with_deadline(
            loop.run_in_executor(None, socket.getaddrinfo, hostname, None),
            DNS_LOOKUP_TIMEOUT_SECONDS,
        )
        return list({r[4][0] for r in results})
    except Exception:
        return []
