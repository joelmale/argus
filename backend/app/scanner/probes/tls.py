"""
TLS Certificate Probe

TLS certificates are among the most reliable device fingerprinting sources.
Self-signed certs often contain the manufacturer's name in the CN or O field.
For example:
  - "Synology Inc." in the cert → it's a Synology NAS
  - "FRITZ!Box" → AVM router
  - "Ubiquiti Networks" → Ubiquiti device
  - "Home Assistant" → HA instance
  - "Proxmox Virtual Environment" → Proxmox host

SANs (Subject Alternative Names) also reveal hostnames the device thinks it has.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import ssl
import time
from datetime import datetime

from app.scanner.models import ProbeResult, TlsProbeData

log = logging.getLogger(__name__)


async def probe(ip: str, port: int = 443, timeout: float = 5.0) -> ProbeResult:
    """Extract TLS certificate information from an SSL/TLS service."""
    t0 = time.monotonic()

    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert_sync, ip, port),
            timeout=timeout,
        )
        if result is None:
            return ProbeResult(probe_type="tls", target_port=port, success=False, error="No certificate")
    except asyncio.TimeoutError:
        return ProbeResult(probe_type="tls", target_port=port, success=False, error="Timeout")
    except Exception as exc:
        return ProbeResult(probe_type="tls", target_port=port, success=False, error=str(exc)[:200])

    return ProbeResult(
        probe_type="tls",
        target_port=port,
        success=True,
        duration_ms=round((time.monotonic() - t0) * 1000, 1),
        data=result.model_dump(),
        raw=_cert_summary(result),
    )


def _get_cert_sync(ip: str, port: int) -> TlsProbeData | None:
    """Synchronous TLS handshake — runs in thread executor."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE   # Accept self-signed certs — very common on LAN

    try:
        with ssl.create_default_context().wrap_socket(
            __import__("socket").create_connection((ip, port), timeout=4),
            server_hostname=ip,
        ) as ssock:
            cert = ssock.getpeercert()
            cert_der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            tls_ver = ssock.version()
            return _parse_cert(cert, cert_der, cipher, tls_ver)
    except ssl.SSLError:
        # Retry without hostname verification (catches self-signed properly)
        try:
            import socket
            raw_sock = socket.create_connection((ip, port), timeout=4)
            ssock = ctx.wrap_socket(raw_sock, server_hostname=ip)
            cert = ssock.getpeercert()
            cert_der = ssock.getpeercert(binary_form=True)
            cipher = ssock.cipher()
            tls_ver = ssock.version()
            ssock.close()
            return _parse_cert(cert, cert_der, cipher, tls_ver)
        except Exception:
            return None
    except Exception:
        return None


def _parse_cert(cert: dict, cert_der: bytes | None, cipher: tuple | None, tls_ver: str | None) -> TlsProbeData:
    data = TlsProbeData()

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer", []))

    data.subject_cn = subject.get("commonName")
    data.cert_org   = subject.get("organizationName")
    data.issuer     = issuer.get("commonName") or issuer.get("organizationName")

    # Self-signed: issuer == subject
    data.is_self_signed = (
        subject.get("commonName") == issuer.get("commonName")
        or subject.get("organizationName") == issuer.get("organizationName")
    )
    if cert_der:
        data.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()

    # SANs
    for typ, val in cert.get("subjectAltName", []):
        if typ == "DNS":
            data.subject_san.append(val)

    # Validity period
    fmt = "%b %d %H:%M:%S %Y %Z"
    nb = cert.get("notBefore")
    na = cert.get("notAfter")
    if nb:
        try:
            data.not_before = datetime.strptime(nb, fmt).isoformat()
        except ValueError:
            data.not_before = nb
    if na:
        try:
            data.not_after = datetime.strptime(na, fmt).isoformat()
        except ValueError:
            data.not_after = na

    # TLS metadata
    data.tls_version = tls_ver
    if cipher:
        data.cipher_suite = cipher[0]

    return data


def _cert_summary(d: TlsProbeData) -> str:
    lines = [f"TLS {d.tls_version or '?'} | Cipher: {d.cipher_suite or '?'}"]
    lines.append(f"Subject CN: {d.subject_cn or '?'} | Org: {d.cert_org or '?'}")
    lines.append(f"Issuer: {d.issuer or '?'} | Self-signed: {d.is_self_signed}")
    if d.subject_san:
        lines.append(f"SANs: {', '.join(d.subject_san[:10])}")
    lines.append(f"Valid: {d.not_before or '?'} → {d.not_after or '?'}")
    return "\n".join(lines)
