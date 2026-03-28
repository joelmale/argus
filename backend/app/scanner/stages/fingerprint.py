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

SNMP_MANAGED_HINT_CLASSES = {
    DeviceClass.ROUTER,
    DeviceClass.SWITCH,
    DeviceClass.ACCESS_POINT,
    DeviceClass.FIREWALL,
    DeviceClass.PRINTER,
    DeviceClass.NAS,
    DeviceClass.VOIP,
}


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
    (37777,  None,              DeviceClass.IP_CAMERA,      0.90, "Dahua service port"),
    (37778,  None,              DeviceClass.IP_CAMERA,      0.86, "Dahua service port"),
    (1935,   None,              DeviceClass.SMART_TV,       0.60, "RTMP streaming"),
    (7000,   None,              DeviceClass.SMART_TV,       0.78, "AirPlay receiver"),
    (7100,   None,              DeviceClass.SMART_TV,       0.75, "AirPlay mirroring"),
    (8008,   None,              DeviceClass.SMART_TV,       0.84, "Chromecast HTTP service"),
    (8009,   None,              DeviceClass.SMART_TV,       0.88, "Chromecast Cast service"),
    (8060,   None,              DeviceClass.SMART_TV,       0.90, "Roku ECP service"),
    (3478,   None,              DeviceClass.GAME_CONSOLE,   0.64, "Console/STUN service"),
    (3479,   None,              DeviceClass.GAME_CONSOLE,   0.64, "Console/STUN service"),
    (3480,   None,              DeviceClass.GAME_CONSOLE,   0.64, "Console/STUN service"),
    (9308,   None,              DeviceClass.GAME_CONSOLE,   0.78, "PlayStation Remote Play service"),
    (5353,   "mdns",            DeviceClass.IOT_DEVICE,     0.40, "mDNS (many devices)"),
    (1900,   "upnp",            DeviceClass.IOT_DEVICE,     0.40, "UPnP (many devices)"),
    (161,    "snmp",            DeviceClass.ROUTER,         0.55, "SNMP-managed device"),
    (179,    "bgp",             DeviceClass.ROUTER,         0.95, "BGP routing protocol"),
    (520,    "rip",             DeviceClass.ROUTER,         0.90, "RIP routing protocol"),
    (5060,   "sip",             DeviceClass.VOIP,           0.90, "SIP VoIP"),
    (5061,   "sip",             DeviceClass.VOIP,           0.92, "SIP TLS VoIP"),
    (1720,   "h323",            DeviceClass.VOIP,           0.90, "H.323 VoIP"),
    (2000,   "cisco-sccp",      DeviceClass.VOIP,           0.90, "Cisco SCCP VoIP"),
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
    mac_vendor_lower = (mac_vendor or "").lower()
    host_name = (host.nmap_hostname or "").lower()
    candidates = _collect_device_hints(open_ports, os_fp, host_name, mac_vendor_lower, host, mac_vendor)

    if not candidates:
        return DeviceHint(DeviceClass.UNKNOWN, 0.0, "No matching signatures")

    return max(candidates, key=lambda h: h.confidence)


def _collect_device_hints(
    open_ports: dict[int, PortResult],
    os_fp: OSFingerprint,
    host_name: str,
    mac_vendor_lower: str,
    host: DiscoveredHost,
    mac_vendor: str | None,
) -> list[DeviceHint]:
    candidates: list[DeviceHint] = []
    candidates.extend(_collect_os_hints(os_fp))
    candidates.extend(_collect_port_signature_hints(open_ports))
    candidates.extend(_collect_port_pattern_hints(open_ports))
    candidates.extend(_collect_hostname_hints(host_name, host))
    candidates.extend(_collect_vendor_hints(mac_vendor_lower, open_ports, mac_vendor))
    return candidates


def _collect_os_hints(os_fp: OSFingerprint) -> list[DeviceHint]:
    candidates: list[DeviceHint] = []

    os_name_lower = (os_fp.os_name or "").lower()
    for keyword, cls in OS_SIGNATURES.items():
        if keyword in os_name_lower:
            candidates.append(DeviceHint(cls, 0.6, f"OS fingerprint: {os_fp.os_name}"))
            break

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
    return candidates


def _collect_port_signature_hints(open_ports: dict[int, PortResult]) -> list[DeviceHint]:
    candidates: list[DeviceHint] = []
    for port_num, svc_substr, cls, conf, reason in PORT_SIGNATURES:
        if port_num is not None and port_num not in open_ports:
            continue
        if svc_substr is not None:
            port_obj = open_ports.get(port_num)
            if port_obj and svc_substr not in (port_obj.service or "").lower():
                continue
        candidates.append(DeviceHint(cls, conf, reason))
    return candidates


def _collect_port_pattern_hints(open_ports: dict[int, PortResult]) -> list[DeviceHint]:
    candidates: list[DeviceHint] = []
    port_set = set(open_ports.keys())
    candidates.extend(_base_port_pattern_hints(port_set))
    candidates.extend(_well_known_service_hints(port_set))
    dnsmasq_hint = _dnsmasq_gateway_hint(open_ports, port_set)
    if dnsmasq_hint is not None:
        candidates.append(dnsmasq_hint)
    return candidates


def _base_port_pattern_hints(port_set: set[int]) -> list[DeviceHint]:
    hints: list[DeviceHint] = []
    if port_set & {80, 443} and 22 in port_set and port_set & {161, 179, 520}:
        hints.append(DeviceHint(DeviceClass.ROUTER, 0.80, "Router port pattern (SSH+HTTP+SNMP/BGP)"))
    if port_set & {80, 443} and port_set & {22, 8080, 8443} and 161 in port_set:
        hints.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.78, "Managed AP pattern (web+ssh+snmp)"))
    if port_set & {9100, 515, 631} and port_set & {80, 443, 8080, 8443}:
        hints.append(DeviceHint(DeviceClass.PRINTER, 0.88, "Printer port pattern (print+web admin)"))
    if port_set & {554, 8554, 37777, 37778} and port_set & {80, 443, 8000}:
        hints.append(DeviceHint(DeviceClass.IP_CAMERA, 0.88, "Camera/NVR port pattern"))
    if port_set & {7000, 7100, 8008, 8009, 8060}:
        hints.append(DeviceHint(DeviceClass.SMART_TV, 0.82, "Streaming device port pattern"))
    if port_set & {5060, 5061, 1720, 2000} and port_set & {80, 443}:
        hints.append(DeviceHint(DeviceClass.VOIP, 0.84, "VoIP endpoint pattern"))
    if 445 in port_set and port_set & {2049, 548, 873}:
        hints.append(DeviceHint(DeviceClass.NAS, 0.80, "NAS port pattern (SMB+NFS/AFP/rsync)"))
    if 22 in port_set and not port_set & {161, 179, 520} and not port_set & {9100, 554}:
        hints.append(DeviceHint(DeviceClass.SERVER, 0.50, "SSH without routing protocols"))
    if port_set <= {80, 443, 8080, 8443} and len(port_set) <= 2:
        hints.append(DeviceHint(DeviceClass.IOT_DEVICE, 0.50, "HTTP-only small footprint"))
    return hints


def _well_known_service_hints(port_set: set[int]) -> list[DeviceHint]:
    port_hints = (
        (8006, DeviceClass.SERVER, 0.92, "Proxmox VE web UI"),
        (5000, DeviceClass.NAS, 0.80, "Synology DSM web UI"),
        (5001, DeviceClass.NAS, 0.80, "Synology DSM web UI"),
        (32400, DeviceClass.NAS, 0.82, "Media/NAS service pattern"),
        (8096, DeviceClass.NAS, 0.82, "Media/NAS service pattern"),
        (8123, DeviceClass.IOT_DEVICE, 0.85, "Home Assistant service"),
        (8060, DeviceClass.SMART_TV, 0.92, "Roku service"),
        (8009, DeviceClass.SMART_TV, 0.90, "Chromecast Cast service"),
        (8008, DeviceClass.SMART_TV, 0.86, "Chromecast service"),
        (7000, DeviceClass.SMART_TV, 0.80, "AirPlay service"),
        (7100, DeviceClass.SMART_TV, 0.78, "AirPlay mirroring service"),
        (37777, DeviceClass.IP_CAMERA, 0.92, "Dahua camera service"),
    )
    return [
        DeviceHint(device_class, confidence, reason)
        for port, device_class, confidence, reason in port_hints
        if port in port_set
    ]


def _dnsmasq_gateway_hint(open_ports: dict[int, PortResult], port_set: set[int]) -> DeviceHint | None:
    if 53 not in port_set:
        return None
    dns_port = open_ports.get(53)
    dns_service = f"{dns_port.service or ''} {dns_port.product or ''} {dns_port.version or ''}".lower() if dns_port else ""
    if "dnsmasq" in dns_service and port_set & {22, 80, 443}:
        return DeviceHint(DeviceClass.FIREWALL, 0.86, "dnsmasq gateway pattern")
    return None


def _collect_hostname_hints(host_name: str, host: DiscoveredHost) -> list[DeviceHint]:
    candidates: list[DeviceHint] = []
    if any(token in host_name for token in ("ap", "wap", "wifi", "deco")):
        candidates.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.60, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("sw", "switch")):
        candidates.append(DeviceHint(DeviceClass.SWITCH, 0.68, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("fw", "pfsense", "opnsense")):
        candidates.append(DeviceHint(DeviceClass.FIREWALL, 0.72, f"Hostname hint: {host.nmap_hostname}"))
    if "firewalla" in host_name:
        candidates.append(DeviceHint(DeviceClass.FIREWALL, 0.97, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("nas", "truenas", "synology")):
        candidates.append(DeviceHint(DeviceClass.NAS, 0.75, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("printer", "laserjet", "officejet", "deskjet", "ecotank", "mfc-", "hl-", "xerox", "canon", "epson")):
        candidates.append(DeviceHint(DeviceClass.PRINTER, 0.84, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("camera", "cam-", "cam_", "nvr", "dvr", "doorbell")):
        candidates.append(DeviceHint(DeviceClass.IP_CAMERA, 0.78, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("roku", "chromecast", "bravia", "appletv", "firetv", "shield", "tv-")):
        candidates.append(DeviceHint(DeviceClass.SMART_TV, 0.82, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("yealink", "polycom", "grandstream", "fanvil", "deskphone", "voip")):
        candidates.append(DeviceHint(DeviceClass.VOIP, 0.82, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("ps5", "playstation", "xbox", "switch")):
        candidates.append(DeviceHint(DeviceClass.GAME_CONSOLE, 0.86, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("macbook", "imac", "thinkpad", "latitude", "desktop", "laptop", "workstation")):
        candidates.append(DeviceHint(DeviceClass.WORKSTATION, 0.74, f"Hostname hint: {host.nmap_hostname}"))
    if any(token in host_name for token in ("iphone", "ipad", "pixel", "android")):
        candidates.append(DeviceHint(DeviceClass.IOT_DEVICE, 0.76, f"Hostname hint: {host.nmap_hostname}"))
    return candidates


def _collect_vendor_hints(
    mac_vendor_lower: str,
    open_ports: dict[int, PortResult],
    mac_vendor: str | None,
) -> list[DeviceHint]:
    candidates: list[DeviceHint] = []
    port_set = set(open_ports.keys())
    if "firewalla" in mac_vendor_lower:
        candidates.append(DeviceHint(DeviceClass.FIREWALL, 0.99, f"Vendor hint: {mac_vendor}"))
    if ("sony interactive" in mac_vendor_lower or "playstation" in mac_vendor_lower) and port_set & {3478, 3479, 3480, 9308}:
        candidates.append(DeviceHint(DeviceClass.GAME_CONSOLE, 0.94, f"Vendor hint: {mac_vendor}"))
    if "microsoft" in mac_vendor_lower and port_set & {3074, 3478, 3479, 3480}:
        candidates.append(DeviceHint(DeviceClass.GAME_CONSOLE, 0.84, f"Vendor hint: {mac_vendor}"))
    if "nintendo" in mac_vendor_lower:
        candidates.append(DeviceHint(DeviceClass.GAME_CONSOLE, 0.82, f"Vendor hint: {mac_vendor}"))
    if "ubiquiti" in mac_vendor_lower or "unifi" in mac_vendor_lower:
        if port_set & {8080, 8443, 10001, 1900}:
            candidates.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.82, f"Vendor and ports: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("tp-link", "aruba", "ruckus", "cambium")):
        if port_set & {80, 443, 161}:
            candidates.append(DeviceHint(DeviceClass.ACCESS_POINT, 0.86, f"Vendor and ports: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("cisco", "juniper", "mikrotik", "netgate")):
        candidates.append(DeviceHint(DeviceClass.ROUTER, 0.72, f"Vendor hint: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("fortinet", "palo alto", "sonicwall", "watchguard", "checkpoint", "sophos")):
        candidates.append(DeviceHint(DeviceClass.FIREWALL, 0.84, f"Vendor hint: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("synology", "qnap", "asustor")):
        candidates.append(DeviceHint(DeviceClass.NAS, 0.85, f"Vendor hint: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("hp", "hewlett", "brother", "epson", "canon", "xerox", "lexmark", "ricoh", "kyocera", "zebra", "oki")):
        if port_set & {9100, 515, 631, 80, 443}:
            candidates.append(DeviceHint(DeviceClass.PRINTER, 0.78, f"Vendor and ports: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("hikvision", "dahua", "reolink", "axis", "amcrest", "foscam", "wyze", "uniview")):
        candidates.append(DeviceHint(DeviceClass.IP_CAMERA, 0.82, f"Vendor hint: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("roku", "vizio", "hisense", "tcl", "lg", "lg electronics")) and port_set & {7000, 7100, 8008, 8009, 8060, 80, 443}:
        candidates.append(DeviceHint(DeviceClass.SMART_TV, 0.84, f"Vendor and ports: {mac_vendor}"))
    if "samsung" in mac_vendor_lower and port_set & {7000, 7100, 8008, 8009, 8060}:
        candidates.append(DeviceHint(DeviceClass.SMART_TV, 0.82, f"Vendor and ports: {mac_vendor}"))
    if "sony" in mac_vendor_lower and not port_set & {3478, 3479, 3480, 9308} and port_set & {7000, 7100, 80, 443}:
        candidates.append(DeviceHint(DeviceClass.SMART_TV, 0.80, f"Vendor and ports: {mac_vendor}"))
    if any(vendor in mac_vendor_lower for vendor in ("yealink", "grandstream", "polycom", "fanvil", "mitel", "obihai")):
        if port_set & {5060, 5061, 80, 443, 2000}:
            candidates.append(DeviceHint(DeviceClass.VOIP, 0.86, f"Vendor and ports: {mac_vendor}"))
    return candidates


def probe_priority(
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

    # SNMP — current port scans are TCP-first, so infra-class devices may still be
    # good SNMP candidates even when 161/udp was never explicitly observed.
    if 161 in open_port_nums or hint.device_class in SNMP_MANAGED_HINT_CLASSES:
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
