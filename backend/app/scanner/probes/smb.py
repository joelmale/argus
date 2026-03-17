"""
SMB / NetBIOS Probe

SMB/NetBIOS reveals:
- Computer name (NetBIOS name)
- Workgroup / domain
- OS version string (Windows Server 2019, Samba 4.x, etc.)
- SMB version support (v1/v2/v3)
- Whether signing is required
- Accessible shares (may include default shares: IPC$, C$, ADMIN$)

SMBv1 still existing is a security finding (EternalBlue attack surface).
Guest access on shares is another notable finding.

Uses impacket for low-level SMB interaction, with a pure-TCP fallback
for NetBIOS name lookup.
"""
from __future__ import annotations

import asyncio
import logging
import time

from app.scanner.models import ProbeResult, SmbProbeData

log = logging.getLogger(__name__)


async def probe(ip: str, port: int = 445, timeout: float = 8.0) -> ProbeResult:
    """Probe SMB/NetBIOS on ip:port."""
    t0 = time.monotonic()

    loop = asyncio.get_event_loop()
    try:
        data = await asyncio.wait_for(
            loop.run_in_executor(None, _smb_probe_sync, ip, port),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return ProbeResult(probe_type="smb", target_port=port, success=False, error="Timeout")
    except Exception as exc:
        return ProbeResult(probe_type="smb", target_port=port, success=False, error=str(exc)[:200])

    if data is None:
        return ProbeResult(probe_type="smb", target_port=port, success=False, error="SMB probe returned no data")

    raw = (
        f"NetBIOS Name: {data.netbios_name}\n"
        f"Workgroup: {data.workgroup}\n"
        f"OS: {data.os_string}\n"
        f"SMB Version: {data.smb_version}\n"
        f"Signing Required: {data.signing_required}\n"
        f"Shares: {', '.join(data.shares)}\n"
        f"Guest Access: {data.has_guest_access}"
    )

    return ProbeResult(
        probe_type="smb",
        target_port=port,
        success=True,
        duration_ms=round((time.monotonic() - t0) * 1000, 1),
        data=data.model_dump(),
        raw=raw,
    )


def _smb_probe_sync(ip: str, port: int) -> SmbProbeData | None:
    """
    Attempt SMB probe using impacket.
    Falls back to NetBIOS name lookup if impacket is unavailable.
    """
    data = SmbProbeData()

    # ── Try impacket ─────────────────────────────────────────────────────────
    try:
        from impacket.smbconnection import SMBConnection
        from impacket import smb, smb3

        conn = SMBConnection(ip, ip, sess_port=port, timeout=5)
        try:
            # Get negotiated dialect
            dialect = conn.getDialect()
            if dialect == smb.SMB_DIALECT:
                data.smb_version = "SMBv1 (DANGEROUS)"
            elif dialect == smb3.SMB2_DIALECT_21:
                data.smb_version = "SMBv2.1"
            elif dialect == smb3.SMB2_DIALECT_30:
                data.smb_version = "SMBv3.0"
            elif dialect == smb3.SMB2_DIALECT_311:
                data.smb_version = "SMBv3.1.1"
            else:
                data.smb_version = f"SMB dialect {dialect:#x}"

            data.signing_required = conn.isSigningRequired()
            data.netbios_name = conn.getServerName()
            data.os_string = conn.getServerOS()
            data.workgroup = conn.getServerDomain()

            # Try anonymous/guest share enumeration
            try:
                conn.login("", "")  # null session
                shares = conn.listShares()
                data.shares = [s["shi1_netname"].rstrip("\x00") for s in shares]
                data.has_guest_access = True
            except Exception:
                data.has_guest_access = False

        finally:
            conn.close()

        return data

    except ImportError:
        log.debug("impacket not available, using NetBIOS fallback")
    except Exception as exc:
        log.debug("impacket SMB probe failed: %s", exc)

    # ── Fallback: raw NetBIOS name query (port 137 UDP) ──────────────────────
    netbios_name = _netbios_name_query(ip)
    if netbios_name:
        data.netbios_name = netbios_name
        return data

    return None


def _netbios_name_query(ip: str) -> str | None:
    """Send a NetBIOS Name Service query and extract the workstation name."""
    import socket
    # NetBIOS Name Service wildcard query
    query = (
        b"\xab\xcd"  # Transaction ID
        + b"\x00\x00"  # Flags: query
        + b"\x00\x01"  # QDCOUNT: 1 question
        + (b"\x00\x00" * 3)
        + b"\x20"  # Name length
        + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Encoded wildcard "*"
        + b"\x00"
        + b"\x00\x21"  # QTYPE: NB_STAT
        + b"\x00\x01"  # QCLASS: IN
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(query, (ip, 137))
        response, _ = sock.recvfrom(1024)
        sock.close()

        # Parse response: skip header (12 bytes), then find name entries
        if len(response) < 57:
            return None
        num_names = response[56]
        if num_names == 0 or len(response) < 57 + num_names * 18:
            return None

        for i in range(num_names):
            offset = 57 + i * 18
            name = response[offset:offset + 15].decode("ascii", errors="replace").strip()
            name_type = response[offset + 15]
            if name_type == 0x00:  # Workstation service
                return name

    except Exception:
        pass
    return None
