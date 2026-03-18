"""
Stage 3 — Service Fingerprinting & Device Heuristics

Takes port scan results and applies rule-based heuristics to make initial
device type guesses before the AI agent takes over. Think of this as the
"fast path" — cheap pattern matching that handles obvious cases instantly
and primes the AI with a good starting hypothesis.

Port → device type mapping is like a Bayesian prior: port 9100 (JetDirect)
means printer with extremely high probability, while port 80 alone is nearly
useless without more context. We combine multiple signals.
"""
from __future__ import annotations

import logging
from typing import NamedTuple

from app.scanner.models import DeviceClass, DiscoveredHost, OSFingerprint, PortResult

log = logging.getLogger(__name__)


class DeviceHint(NamedTuple):
    device_class: DeviceClass
    confidence: float    # 0.0–1.0
    reason: str


# ─── Port signature table ────────────────────────────────────────────────────
# Maps (port, service_substring) → (DeviceClass, confidence, label)
# More specific rules listed first; evaluation stops at first confident match.

PORT_SIGNATURES: list[tuple[int | None, str | None, DeviceClass, float, str]] = [
    # port,  service_substr,    class,              conf,  reason
    (9100,   None,              DeviceClass.PRINTER,        0.95, "JetDirect print port"),
    (515,    None,              DeviceClass.PRINTER,        0.90, "LPD print spooler"),
    (631,    "ipp",             DeviceClass.PRINTER,        0.90, "IPP printing"),
    (8080,   "ipp",             DeviceClass.PRINTER,        0.85, "IPP on alt port"),
    (554,    None,              DeviceClass.IP_CAMERA,      0.85, "RTSP video stream"),
    (8554,   "rtsp",            DeviceClass.IP_CAMERA,      0.85, "RTSP on alt port"),
    (1935,   None,              DeviceClass.SMART_TV,       0.60, "RTMP streaming"),
    (5353,   "mdns",            DeviceClass.IOT_DEVICE,     0.40, "mDNS (many devices)"),
    (1900,   "upnp",            DeviceClass.IOT_DEVICE,     0.40, "UPnP (many devices)"),
    (161,    "snmp",            DeviceClass.ROUTER,         0.55, "SNMP-managed device"),
    (179,    "bgp",             DeviceClass.ROUTER,         0.95, "BGP routing protocol"),
    (520,    "rip",             DeviceClass.ROUTER,         0.90, "RIP routing protocol"),
    (5060,   "sip",             DeviceClass.VOIP,           0.90, "SIP VoIP"),
    (1720,   "h323",            DeviceClass.VOIP,           0.90, "H.323 VoIP"),
    (445,    "smb",             DeviceClass.SERVER,         0.55, "SMB file sharing"),
    (3389,   "rdp",             DeviceClass.WORKSTATION,    0.75, "Remote Desktop"),
    (5985,   "winrm",           DeviceClass.SERVER,         0.70, "WinRM"),
    (2049,   "nfs",             DeviceClass.NAS,            0.80, "NFS share"),
    (548,    "afp",             DeviceClass.NAS,            0.85, "AFP (Apple file sharing)"),
    (8096,   None,              DeviceClass.NAS,            0.75, "Jellyfin/Emby media"),
    (32400,  None,              DeviceClass.NAS,            0.80, "Plex Media Server"),
    (8123,   None,              DeviceClass.IOT_DEVICE,     0.80, "Home Assistant"),
    (1883,   "mqtt",            DeviceClass.IOT_DEVICE,     0.85, "MQTT broker"),
    (8883,   "mqtt",            DeviceClass.IOT_DEVICE,     0.85, "MQTT TLS broker"),
    (6443,   None,              DeviceClass.SERVER,         0.75, "Kubernetes API"),
    (2375,   None,              DeviceClass.SERVER,         0.80, "Docker daemon"),
    (2376,   None,              DeviceClass.SERVER,         0.80, "Docker daemon TLS"),
]

# OS family hints
OS_SIGNATURES: dict[str, DeviceClass] = {
    "windows":     DeviceClass.WORKSTATION,
    "linux":       DeviceClass.SERVER,       # refined by port context
    "ios":         DeviceClass.IOT_DEVICE,   # iPhone/iPad (rare to see scanned)
    "mac os":      DeviceClass.WORKSTATION,
    "android":     DeviceClass.IOT_DEVICE,
    "freebsd":     DeviceClass.SERVER,
    "embedded":    DeviceClass.IOT_DEVICE,
    "cisco ios":   DeviceClass.ROUTER,
    "junos":       DeviceClass.ROUTER,
    "mikrotik":    DeviceClass.ROUTER,
    "dd-wrt":      DeviceClass.ROUTER,
    "openwrt":     DeviceClass.ROUTER,
    "fortios":     DeviceClass.FIREWALL,
    "pfsense":     DeviceClass.FIREWALL,
    "opnsense":    DeviceClass.FIREWALL,
    "proxmox":     DeviceClass.SERVER,
    "esxi":        DeviceClass.SERVER,
    "truenas":     DeviceClass.NAS,
    "freenas":     DeviceClass.NAS,
    "synology":    DeviceClass.NAS,
    "qnap":        DeviceClass.NAS,
}


def classify(
    host: DiscoveredHost,
    ports: list[PortResult],
    os_fp: OSFingerprint,
    mac_vendor: str | None = None,
) -> DeviceHint:
    """
    Apply heuristic rules to make an initial device classification.
    Returns the best guess with a confidence score.
    """
    open_ports = {p.port: p for p in ports if p.state == "open"}
    candidates: list[DeviceHint] = []
    mac_vendor_lower = (mac_vendor or "").lower()
    host_name = (host.nmap_hostname or "").lower()

    # 1. OS fingerprint hints
    os_name_lower = (os_fp.os_name or "").lower()
    for keyword, cls in OS_SIGNATURES.items():
        if keyword in os_name_lower:
            candidates.append(DeviceHint(cls, 0.6, f"OS fingerprint: {os_fp.os_name}"))
            break

    # nmap device type hint
    nmap_type = (os_fp.device_type or "").lower()
    if "router" in nmap_type or "switch" in nmap_type:
        candidates.append(DeviceHint(DeviceClass.ROUTER, 0.70, f"nmap device type: {os_fp.device_type}"))
    elif "printer" in nmap_type:
        candidates.append(DeviceHint(DeviceClass.PRINTER, 0.80, f"nmap device type: {os_fp.device_type}"))
    elif "media" in nmap_type:
        candidates.append(DeviceHint(DeviceClass.SMART_TV, 0.70, f"nmap device type: {os_fp.device_type}"))
    elif "wap" in nmap_type or "access point" in nmap_type:
        candidates.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.80, f"nmap device type: {os_fp.device_type}"))
    elif "firewall" in nmap_type:
        candidates.append(DeviceHint(DeviceClass.FIREWALL, 0.80, f"nmap device type: {os_fp.device_type}"))

    # 2. Port signature matching
    for port_num, svc_substr, cls, conf, reason in PORT_SIGNATURES:
        if port_num is not None and port_num not in open_ports:
            continue
        if svc_substr is not None:
            port_obj = open_ports.get(port_num)
            if port_obj and svc_substr not in (port_obj.service or "").lower():
                continue
        candidates.append(DeviceHint(cls, conf, reason))

    # 3. Composite port set analysis
    port_set = set(open_ports.keys())

    # Router/AP pattern: 22 + 80 + 443 + (161 or 179)
    if port_set & {80, 443} and port_set & {22} and port_set & {161, 179, 520}:
        candidates.append(DeviceHint(DeviceClass.ROUTER, 0.80, "Router port pattern (SSH+HTTP+SNMP/BGP)"))

    # Access point / wireless controller pattern
    if port_set & {80, 443} and port_set & {22, 8080, 8443} and 161 in port_set:
        candidates.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.78, "Managed AP pattern (web+ssh+snmp)"))

    # NAS pattern: 445 + (2049 or 548 or 873)
    if 445 in port_set and port_set & {2049, 548, 873}:
        candidates.append(DeviceHint(DeviceClass.NAS, 0.80, "NAS port pattern (SMB+NFS/AFP/rsync)"))

    # Server pattern: SSH + no router protocols
    if 22 in port_set and not port_set & {161, 179, 520} and not port_set & {9100, 554}:
        candidates.append(DeviceHint(DeviceClass.SERVER, 0.50, "SSH without routing protocols"))

    # Bare HTTP/HTTPS only → likely IoT/embedded
    if port_set <= {80, 443, 8080, 8443} and len(port_set) <= 2:
        candidates.append(DeviceHint(DeviceClass.IOT_DEVICE, 0.50, "HTTP-only small footprint"))

    # Homelab virtualization / infrastructure
    if 8006 in port_set:
        candidates.append(DeviceHint(DeviceClass.SERVER, 0.92, "Proxmox VE web UI"))
    if 5000 in port_set or 5001 in port_set:
        candidates.append(DeviceHint(DeviceClass.NAS, 0.80, "Synology DSM web UI"))
    if 32400 in port_set or 8096 in port_set:
        candidates.append(DeviceHint(DeviceClass.NAS, 0.82, "Media/NAS service pattern"))
    if 8123 in port_set:
        candidates.append(DeviceHint(DeviceClass.IOT_DEVICE, 0.85, "Home Assistant service"))

    # Common hostname/vendor hints in homelabs
    if any(token in host_name for token in ("ap", "wap", "wifi", "deco")):
        candidates.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.60, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("sw", "switch")):
        candidates.append(DeviceHint(DeviceClass.SWITCH, 0.68, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("fw", "pfsense", "opnsense")):
        candidates.append(DeviceHint(DeviceClass.FIREWALL, 0.72, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("nas", "truenas", "synology")):
        candidates.append(DeviceHint(DeviceClass.NAS, 0.75, f"Hostname hint: {host.nmap_hostname}"))

    if "ubiquiti" in mac_vendor_lower or "unifi" in mac_vendor_lower:
        if port_set & {8080, 8443, 10001, 1900}:
            candidates.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.82, f"Vendor and ports: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("tp-link", "aruba", "ruckus", "cambium")):
        if port_set & {80, 443, 161}:
            candidates.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.86, f"Vendor and ports: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("cisco", "juniper", "mikrotik", "netgate")):
        candidates.append(DeviceHint(DeviceClass.ROUTER, 0.72, f"Vendor hint: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("synology", "qnap", "asustor")):
        candidates.append(DeviceHint(DeviceClass.NAS, 0.85, f"Vendor hint: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("hp", "hewlett", "brother", "epson", "canon", "xerox")):
        if port_set & {9100, 515, 631, 80, 443}:
            candidates.append(DeviceHint(DeviceClass.PRINTER, 0.78, f"Vendor and ports: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("hikvision", "dahua", "reolink", "axis")):
        candidates.append(DeviceHint(DeviceClass.IP_CAMERA, 0.82, f"Vendor hint: {mac_vendor}"))

    if not candidates:
        return DeviceHint(DeviceClass.UNKNOWN, 0.0, "No matching signatures")

    # Return highest-confidence hint
    return max(candidates, key=lambda h: h.confidence)


def probe_priority(
    host: DiscoveredHost,
    ports: list[PortResult],
    hint: DeviceHint,
) -> list[str]:
    """
    Suggest which probes to run based on open ports and device hint.
    Returns probe type names in priority order.

    This primes the AI agent's investigation plan — the agent can
    follow this list or deviate based on its own reasoning.
    """
    open_port_nums = {p.port for p in ports if p.state == "open"}
    priority: list[str] = []

    # Always try reverse DNS
    priority.append("dns")

    # HTTP/HTTPS — extremely high signal
    if open_port_nums & {80, 8080, 8000, 8008, 8888}:
        priority.append("http")
    if open_port_nums & {443, 8443, 4443}:
        priority.append("tls")

    # SSH — version and algorithms reveal a lot
    if 22 in open_port_nums or 2222 in open_port_nums:
        priority.append("ssh")

    # SNMP — gold mine for managed devices
    if 161 in open_port_nums:
        priority.append("snmp")

    # mDNS — IoT and Apple device identification
    if 5353 in open_port_nums or hint.device_class in (DeviceClass.IOT_DEVICE, DeviceClass.SMART_TV):
        priority.append("mdns")

    # UPnP — consumer device identification
    if 1900 in open_port_nums or hint.device_class in (DeviceClass.IOT_DEVICE, DeviceClass.ROUTER):
        priority.append("upnp")

    # SMB — Windows/NAS identification
    if open_port_nums & {445, 139}:
        priority.append("smb")

    return priority
