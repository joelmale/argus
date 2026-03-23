"""
SSH Banner & Algorithm Probe

The SSH banner is a high-signal fingerprint source. Examples:
  SSH-2.0-OpenSSH_9.3p2 Ubuntu-1ubuntu3.6  → Ubuntu server
  SSH-2.0-OpenSSH_8.4p1 Raspbian           → Raspberry Pi
  SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10 → Old Ubuntu (EOL!)
  SSH-2.0-dropbear_2022.83                  → Embedded Linux (router/IoT)
  SSH-2.0-ROSSSH                            → RouterOS (MikroTik)
  SSH-2.0-Cisco-1.25                        → Cisco IOS

Key exchange algorithms also reveal a lot about the device's security posture.
Ancient algorithms (diffie-hellman-group1-sha1, arcfour) signal outdated firmware.
"""
from __future__ import annotations

import asyncio
import logging
import time

from app.scanner.models import ProbeResult, SshProbeData

log = logging.getLogger(__name__)

SSH_PROBE_TIMEOUT_SECONDS = 5.0


async def _await_with_deadline(awaitable, deadline_seconds: float):
    timeout_context = getattr(asyncio, "timeout", None)
    if timeout_context is not None:
        async with timeout_context(deadline_seconds):
            return await awaitable
    return await asyncio.wait_for(awaitable, timeout=deadline_seconds)


async def probe(ip: str, port: int = 22) -> ProbeResult:
    """Connect to SSH port, grab banner and algorithm negotiation."""
    t0 = time.monotonic()

    try:
        data = await _await_with_deadline(_grab_ssh_info(ip, port), SSH_PROBE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        return ProbeResult(probe_type="ssh", target_port=port, success=False, error="Timeout")
    except Exception as exc:
        return ProbeResult(probe_type="ssh", target_port=port, success=False, error=str(exc)[:200])

    if data is None:
        return ProbeResult(probe_type="ssh", target_port=port, success=False, error="No response")

    raw = (
        f"Banner: {data.banner}\n"
        f"KEX: {', '.join(data.kex_algorithms[:5])}\n"
        f"HostKey: {', '.join(data.host_key_algorithms[:5])}\n"
        f"Encryption: {', '.join(data.encryption_algorithms[:5])}"
    )

    return ProbeResult(
        probe_type="ssh",
        target_port=port,
        success=True,
        duration_ms=round((time.monotonic() - t0) * 1000, 1),
        data=data.model_dump(),
        raw=raw,
    )


async def _grab_ssh_info(ip: str, port: int) -> SshProbeData | None:
    """
    Connect at TCP level, read the SSH banner, then send our own version string
    to trigger algorithm negotiation. Pure asyncio — no paramiko needed.
    """
    reader, writer = await asyncio.open_connection(ip, port)
    data = SshProbeData()

    try:
        # 1. Read server banner (first line)
        banner_line = await asyncio.wait_for(reader.readline(), timeout=3.0)
        data.banner = banner_line.decode("utf-8", errors="replace").strip()

        # Extract version
        parts = data.banner.split("-")
        if len(parts) >= 3:
            data.server_version = "-".join(parts[2:])

        # 2. Send our banner to start key exchange
        writer.write(b"SSH-2.0-ArgusScanner\r\n")
        await writer.drain()

        # 3. Read KEXINIT packet (type 20)
        # Format: 4-byte length, 1-byte padding, 1-byte type, payload
        header = await asyncio.wait_for(reader.readexactly(5), timeout=3.0)
        pkt_len = int.from_bytes(header[:4], "big")
        if pkt_len > 4096:
            return data   # Malformed, but we got the banner

        payload = await asyncio.wait_for(reader.readexactly(pkt_len - 1), timeout=3.0)

        # Skip: padding(1) + type(1) + cookie(16) = offset 18
        if len(payload) < 20:
            return data

        offset = 2 + 16  # padding_len byte + msg_type byte already consumed + cookie
        data.kex_algorithms    = _read_name_list(payload, offset)
        offset += 4 + sum(len(n) for n in data.kex_algorithms) + len(data.kex_algorithms) - (1 if data.kex_algorithms else 0) + 4
        data.host_key_algorithms = _read_name_list(payload, offset)
        offset += 4 + sum(len(n) for n in data.host_key_algorithms) + len(data.host_key_algorithms) - (1 if data.host_key_algorithms else 0) + 4
        data.encryption_algorithms = _read_name_list(payload, offset)

    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionResetError):
        pass  # We may have gotten partial data — that's fine
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return data if data.banner else None


def _read_name_list(payload: bytes, offset: int) -> list[str]:
    """Parse an SSH name-list: 4-byte length followed by comma-separated names."""
    try:
        if offset + 4 > len(payload):
            return []
        length = int.from_bytes(payload[offset:offset + 4], "big")
        if offset + 4 + length > len(payload):
            return []
        raw = payload[offset + 4: offset + 4 + length].decode("ascii", errors="ignore")
        return [n.strip() for n in raw.split(",") if n.strip()]
    except Exception:
        return []
