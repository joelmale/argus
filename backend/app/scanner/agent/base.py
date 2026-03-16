"""
Base analyst interface + system prompt.

Every AI backend (Ollama, Anthropic, future providers) implements this interface.
The pipeline always calls BaseAnalyst.investigate() — it never knows which
backend is underneath. Classic strategy pattern.

System prompt design notes:
- Explicit about what the agent should and shouldn't do
- Gives a clear investigation framework (hypothesis → targeted probes → synthesis)
- Tells the agent about the "selectively aggressive" philosophy
- Asks for structured final_analysis call to terminate — prevents open-ended rambling
"""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod

from app.scanner.models import (
    AIAnalysis,
    DeviceClass,
    DiscoveredHost,
    HostScanResult,
    OSFingerprint,
    PortResult,
    SecurityFinding,
)

log = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are an expert network security analyst performing automated device investigation for a home lab network management tool called Argus.

Your job is to identify each device on the network as precisely as possible — determining its type, manufacturer, model, operating system, running services, and any notable security characteristics.

## Investigation Approach

1. **Analyze initial data** — Study the nmap port scan results, OS fingerprint, MAC vendor, and any existing heuristic classification. Form an initial hypothesis.

2. **Run targeted probes** — Use your tools to gather more specific information. Be strategic:
   - HTTP probe if there's a web port → page title and server header often directly identify the device
   - TLS probe if HTTPS is open → certificate CN/Org often contains vendor name
   - SSH probe if SSH is open → banner reveals exact OS and sometimes hardware
   - SNMP probe if port 161 is open → sysDescr is the richest single source of device info
   - mDNS probe for IoT/Apple/consumer devices → reveals model names
   - UPnP probe for consumer networking gear → device XML has make/model
   - SMB probe if port 445/139 open → reveals Windows/Samba details

3. **Be selective** — Don't run every probe on every device. Prioritize based on what's open and your current hypothesis. 3-5 probes is usually enough; a device with only port 22 open doesn't need an HTTP probe.

4. **Synthesize and conclude** — When you have enough information, call `final_analysis`. Be specific about what evidence led to each conclusion. If the evidence is ambiguous, say so in investigation_notes and lower your confidence score.

## Security Findings to Watch For
- SMBv1 enabled (EternalBlue attack surface) → severity: high
- Telnet open (cleartext protocol) → severity: high
- FTP open (cleartext) → severity: medium
- Default/common service on unusual port → severity: info
- Self-signed HTTPS certificate (normal for LAN, but note it) → severity: info
- Very old TLS version (SSLv3, TLS 1.0) → severity: medium
- Outdated SSH version (< OpenSSH 7.0) → severity: medium
- Open SNMP with default community "public" → severity: medium
- HTTP with no auth on admin interface → severity: medium

## Output Quality
- investigation_notes should be a clear narrative, not a list of raw data
- confidence of 0.9+ means you found definitive evidence (e.g. UPnP says "NETGEAR R8000")
- confidence of 0.7 means good evidence but could be wrong
- confidence < 0.5 means educated guess — explain why in notes
- If completely unable to determine, device_class = "unknown" and explain what was tried

Call `final_analysis` when done. Do not ask for more information — use only what the tools return.\
"""


def _build_initial_context(
    host: DiscoveredHost,
    ports: list[PortResult],
    os_fp: OSFingerprint,
    mac_vendor: str | None,
    initial_hint_class: str,
    initial_hint_confidence: float,
    probe_priority: list[str],
) -> str:
    """Build the initial investigation context message sent to the agent."""
    open_ports = [p for p in ports if p.state == "open"]

    port_lines = []
    for p in open_ports:
        svc = p.service or "?"
        ver = f" ({p.version})" if p.version else ""
        port_lines.append(f"  {p.port}/{p.protocol} {svc}{ver}")

    lines = [
        f"## Device to investigate: {host.ip_address}",
        "",
        "### Discovery info",
        f"- IP: {host.ip_address}",
        f"- MAC: {host.mac_address or 'unknown'} | Vendor (OUI): {mac_vendor or 'unknown'}",
        f"- Discovery method: {host.discovery_method}",
        f"- TTL hint: {host.ttl or 'n/a'} (64→Linux/iOS, 128→Windows, 255→network device)",
        "",
        "### Port scan results",
        f"Open ports ({len(open_ports)}):",
    ] + port_lines + [
        "",
        "### OS fingerprint",
        f"- OS name: {os_fp.os_name or 'not determined'}",
        f"- OS family: {os_fp.os_family or 'unknown'}",
        f"- Device type hint: {os_fp.device_type or 'unknown'}",
        f"- Accuracy: {os_fp.os_accuracy or '?'}%",
        "",
        "### Heuristic pre-classification",
        f"- Initial guess: {initial_hint_class} (confidence: {initial_hint_confidence:.0%})",
        f"- Recommended probe order: {', '.join(probe_priority) or 'none'}",
        "",
        "Investigate this device now. Use tools as needed, then call final_analysis.",
    ]

    return "\n".join(lines)


def _parse_final_analysis(args: dict) -> AIAnalysis:
    """Convert the final_analysis tool arguments into an AIAnalysis model."""
    try:
        device_class = DeviceClass(args.get("device_class", "unknown"))
    except ValueError:
        device_class = DeviceClass.UNKNOWN

    findings = []
    for f in args.get("security_findings", []):
        try:
            findings.append(SecurityFinding(
                severity=f.get("severity", "info"),
                title=f.get("title", ""),
                detail=f.get("detail", ""),
            ))
        except Exception:
            pass

    return AIAnalysis(
        device_class=device_class,
        confidence=float(args.get("confidence", 0.0)),
        vendor=args.get("vendor"),
        model=args.get("model"),
        os_guess=args.get("os_guess"),
        device_role=args.get("device_role"),
        open_services_summary=args.get("open_services_summary", []),
        security_findings=findings,
        investigation_notes=args.get("investigation_notes", ""),
        suggested_tags=args.get("suggested_tags", []),
    )


class BaseAnalyst(ABC):
    """Abstract base for AI analyst backends."""

    MAX_STEPS = 10  # Maximum tool calls before forcing final_analysis

    @abstractmethod
    async def investigate(self, result: HostScanResult) -> AIAnalysis:
        """Run the full investigation loop and return an AIAnalysis."""
        ...

    def _build_context(self, result: HostScanResult, hint_class: str, hint_conf: float, probe_priority: list[str]) -> str:
        return _build_initial_context(
            result.host,
            result.ports,
            result.os_fingerprint,
            result.mac_vendor,
            hint_class,
            hint_conf,
            probe_priority,
        )

    def _parse_analysis(self, args: dict) -> AIAnalysis:
        return _parse_final_analysis(args)
