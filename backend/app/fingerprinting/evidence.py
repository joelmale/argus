from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.fingerprinting.datasets import lookup_pen_vendor, match_recog_dataset
from app.scanner.models import HostScanResult
from app.scanner.stages.fingerprint import classify


@dataclass(slots=True)
class EvidenceItem:
    source: str
    category: str
    key: str
    value: str
    confidence: float
    details: dict[str, Any]


_HOSTNAME_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _ttl_stack_hint(ttl: int) -> tuple[str, float, dict[str, Any]] | None:
    if ttl <= 0:
        return None
    if ttl <= 70:
        return ("linux_like", 0.42, {"ttl": ttl, "initial_ttl_guess": 64})
    if ttl <= 138:
        return ("windows_like", 0.42, {"ttl": ttl, "initial_ttl_guess": 128})
    if ttl <= 255:
        return ("network_appliance_like", 0.42, {"ttl": ttl, "initial_ttl_guess": 255})
    return None


def _signature_evidence(value: str, source: str, details: dict[str, Any]) -> list[EvidenceItem]:
    text = value.lower()
    matches: list[EvidenceItem] = []
    signatures: list[tuple[str, str, str, float]] = [
        ("proxmox", "device_type", "server", 0.88),
        ("synology", "device_type", "nas", 0.9),
        ("diskstation", "device_type", "nas", 0.9),
        ("qnap", "device_type", "nas", 0.9),
        ("truenas", "device_type", "nas", 0.92),
        ("freenas", "device_type", "nas", 0.9),
        ("unifi", "device_type", "access_point", 0.86),
        ("omada", "device_type", "access_point", 0.84),
        ("deco", "device_type", "access_point", 0.84),
        ("openwrt", "device_type", "router", 0.88),
        ("luci", "device_type", "router", 0.82),
        ("routeros", "device_type", "router", 0.88),
        ("mikrotik", "device_type", "router", 0.88),
        ("pfsense", "device_type", "firewall", 0.92),
        ("opnsense", "device_type", "firewall", 0.92),
        ("jellyfin", "device_type", "server", 0.74),
        ("plex", "device_type", "server", 0.72),
        ("playstation", "device_type", "game_console", 0.94),
        ("ps5", "device_type", "game_console", 0.94),
        ("xbox", "device_type", "game_console", 0.9),
        ("nintendo switch", "device_type", "game_console", 0.92),
        ("home assistant", "device_type", "iot_device", 0.84),
        ("frigate", "device_type", "server", 0.7),
        ("axis", "device_type", "ip_camera", 0.85),
        ("hikvision", "device_type", "ip_camera", 0.85),
        ("dahua", "device_type", "ip_camera", 0.85),
        ("brother", "device_type", "printer", 0.82),
        ("epson", "device_type", "printer", 0.82),
        ("hewlett packard", "device_type", "printer", 0.82),
        ("hp ", "device_type", "printer", 0.76),
        ("canon", "device_type", "printer", 0.82),
        ("ubiquiti", "vendor", "Ubiquiti", 0.88),
        ("synology", "vendor", "Synology", 0.9),
        ("qnap", "vendor", "QNAP", 0.9),
        ("mikrotik", "vendor", "MikroTik", 0.88),
        ("tp-link", "vendor", "TP-Link", 0.86),
        ("tplink", "vendor", "TP-Link", 0.86),
        ("deco", "vendor", "TP-Link", 0.82),
        ("netgate", "vendor", "Netgate", 0.88),
        ("sony interactive entertainment", "vendor", "Sony", 0.94),
        ("playstation", "vendor", "Sony", 0.92),
        ("xbox", "vendor", "Microsoft", 0.88),
        ("nintendo", "vendor", "Nintendo", 0.88),
    ]
    for needle, category, normalized, confidence in signatures:
        if needle in text:
            matches.append(EvidenceItem(source, category, f"signature:{needle}", normalized, confidence, details))
    return matches


def _hostname_signature_evidence(hostname: str, source: str, details: dict[str, Any]) -> list[EvidenceItem]:
    tokens = _hostname_tokens(hostname)
    if not tokens:
        return []

    enriched_details = {**details, "hostname": hostname, "hostname_tokens": sorted(tokens)}
    matches: list[EvidenceItem] = []
    seen: set[tuple[str, str, str, str]] = set()

    for variant in _hostname_text_variants(hostname):
        for item in _signature_evidence(variant, source, enriched_details):
            _append_unique_evidence(matches, seen, item)

    for token, category, key, value, confidence in _hostname_role_matches(tokens):
        _append_unique_evidence(
            matches,
            seen,
            EvidenceItem(
                source,
                category,
                key,
                value,
                confidence,
                {**enriched_details, "hostname_match": token},
            ),
        )

    return matches


def _hostname_tokens(hostname: str) -> set[str]:
    labels = hostname.lower().split(".")
    primary_label = labels[0] if labels else hostname.lower()
    return {token for token in _HOSTNAME_TOKEN_RE.findall(primary_label) if token}


def _hostname_text_variants(hostname: str) -> list[str]:
    primary_label = hostname.lower().split(".")[0]
    ordered_tokens = _HOSTNAME_TOKEN_RE.findall(primary_label)
    variants = [
        hostname.lower(),
        primary_label,
        " ".join(ordered_tokens),
        "".join(ordered_tokens),
    ]
    return [variant for index, variant in enumerate(variants) if variant and variant not in variants[:index]]


def _hostname_role_matches(tokens: set[str]) -> list[tuple[str, str, str, str, float]]:
    role_signatures: list[tuple[set[str], str, str, float]] = [
        ({"nas", "storage", "fileserver"}, "device_type", "nas", 0.82),
        ({"router", "gateway", "gw"}, "device_type", "router", 0.80),
        ({"firewall", "fw"}, "device_type", "firewall", 0.80),
        ({"switch", "sw"}, "device_type", "switch", 0.80),
        ({"ap", "wap", "wifi", "wlan", "uap", "eap"}, "device_type", "access_point", 0.78),
        ({"printer", "print", "laserjet", "officejet", "deskjet", "ecotank", "mfc"}, "device_type", "printer", 0.82),
        ({"camera", "cam", "nvr", "dvr", "doorbell"}, "device_type", "ip_camera", 0.78),
        ({"roku", "chromecast", "bravia", "appletv", "firetv", "shield", "tv"}, "device_type", "smart_tv", 0.82),
        ({"voip", "deskphone", "yealink", "polycom", "grandstream", "fanvil"}, "device_type", "voip", 0.82),
        ({"ps5", "ps4", "playstation", "xbox"}, "device_type", "game_console", 0.86),
        ({"server", "srv", "pve", "esxi", "docker", "k8s", "kubernetes"}, "device_type", "server", 0.76),
        ({"desktop", "laptop", "workstation", "macbook", "imac", "thinkpad", "latitude"}, "device_type", "workstation", 0.74),
        ({"iphone", "ipad", "pixel", "android", "homeassistant", "hassio", "hass", "thermostat"}, "device_type", "iot_device", 0.76),
        ({"macbook", "imac", "iphone", "ipad", "appletv"}, "vendor", "Apple", 0.78),
    ]

    matches: list[tuple[str, str, str, str, float]] = []
    for aliases, category, value, confidence in role_signatures:
        matched = tokens & aliases
        if not matched:
            continue
        if value == "switch" and "nintendo" in tokens:
            continue
        for token in sorted(matched):
            matches.append((token, category, f"hostname:{token}", value, confidence))
    if "nintendo" in tokens and "switch" in tokens:
        matches.append(("nintendo switch", "device_type", "hostname:nintendo_switch", "game_console", 0.88))
        matches.append(("nintendo", "vendor", "hostname:nintendo", "Nintendo", 0.86))
    if "home" in tokens and "assistant" in tokens:
        matches.append(("home assistant", "device_type", "hostname:home_assistant", "iot_device", 0.84))
    return matches


def _append_unique_evidence(
    matches: list[EvidenceItem],
    seen: set[tuple[str, str, str, str]],
    item: EvidenceItem,
) -> None:
    identity = (item.source, item.category, item.key, item.value)
    if identity in seen:
        return
    seen.add(identity)
    matches.append(item)


def extract_evidence(result: HostScanResult) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []
    _append_basic_evidence(evidence, result)
    _append_rule_evidence(evidence, result)
    _append_ai_evidence(evidence, result)
    _append_probe_evidence(evidence, result)
    return evidence


def _append_basic_evidence(evidence: list[EvidenceItem], result: HostScanResult) -> None:
    if result.mac_vendor:
        evidence.append(EvidenceItem("mac_oui", "vendor", "mac_vendor", result.mac_vendor, 0.72, {}))

    ttl = result.host.ttl
    if ttl is not None:
        evidence.append(EvidenceItem("tcpip_stack", "os_hint", "ttl", str(ttl), 0.30, {"ttl": ttl}))
        ttl_hint = _ttl_stack_hint(ttl)
        if ttl_hint:
            value, confidence, details = ttl_hint
            evidence.append(EvidenceItem("tcpip_stack", "os_hint", "ttl_family", value, confidence, details))

    _append_os_fingerprint_evidence(evidence, result)
    _append_hostname_evidence(evidence, result.reverse_hostname)
    _append_port_evidence(evidence, result)


def _append_os_fingerprint_evidence(evidence: list[EvidenceItem], result: HostScanResult) -> None:
    if not result.os_fingerprint.os_name or not result.os_fingerprint.os_accuracy:
        return
    evidence.append(
        EvidenceItem(
            "nmap_os",
            "os",
            "os_name",
            result.os_fingerprint.os_name,
            min(result.os_fingerprint.os_accuracy / 100.0, 0.95),
            {
                "accuracy": result.os_fingerprint.os_accuracy,
                "os_family": result.os_fingerprint.os_family,
                "os_version": result.os_fingerprint.os_version,
                "device_type_hint": result.os_fingerprint.device_type,
                "cpe": result.os_fingerprint.cpe,
            },
        )
    )


def _append_hostname_evidence(evidence: list[EvidenceItem], reverse_hostname: str | None) -> None:
    if not reverse_hostname:
        return
    details = {"hostname": reverse_hostname}
    evidence.append(EvidenceItem("hostname", "identity", "hostname", reverse_hostname, 0.60, {}))
    evidence.extend(_hostname_signature_evidence(reverse_hostname, "hostname", details))


def _append_port_evidence(evidence: list[EvidenceItem], result: HostScanResult) -> None:
    for port in result.open_ports:
        details = {
            "port": port.port,
            "protocol": port.protocol,
            "product": port.product,
            "version": port.version,
            "cpe": port.cpe,
        }
        evidence.append(
            EvidenceItem(
                "nmap_service",
                "service",
                f"{port.port}/{port.protocol}",
                port.service or "unknown",
                0.75,
                details,
            )
        )
        _append_port_banner_recog_evidence(evidence, port.service, port.banner, details)


def _append_rule_evidence(evidence: list[EvidenceItem], result: HostScanResult) -> None:
    rule_hint = classify(result.host, result.ports, result.os_fingerprint, result.mac_vendor)
    if rule_hint.device_class.value == "unknown":
        return
    evidence.append(
        EvidenceItem(
            "rule",
            "device_type",
            "classified_type",
            rule_hint.device_class.value,
            rule_hint.confidence,
            {"reason": rule_hint.reason},
        )
    )


def _append_ai_evidence(evidence: list[EvidenceItem], result: HostScanResult) -> None:
    ai = result.ai_analysis
    if ai is None:
        return
    if ai.device_class.value != "unknown":
        evidence.append(
            EvidenceItem(
                "ai",
                "device_type",
                "classified_type",
                ai.device_class.value,
                ai.confidence,
                {"backend": ai.ai_backend, "model": ai.model_used, "role": ai.device_role},
            )
        )
    _append_optional_evidence(evidence, "ai", "vendor", "vendor", ai.vendor, ai.confidence)
    _append_optional_evidence(evidence, "ai", "model", "model", ai.model, ai.confidence)
    _append_optional_evidence(evidence, "ai", "os", "os_guess", ai.os_guess, ai.confidence)


def _append_probe_evidence(evidence: list[EvidenceItem], result: HostScanResult) -> None:
    for probe in result.probes:
        if not probe.success:
            continue
        data = probe.data or {}
        if probe.probe_type in {"http", "https"}:
            _append_http_probe_evidence(evidence, data)
        elif probe.probe_type == "tls":
            _append_tls_probe_evidence(evidence, data)
        elif probe.probe_type == "ssh":
            _append_optional_probe_signature(evidence, "probe_ssh", "service", "ssh_banner", data.get("banner"), 0.80, data)
            _append_recog_evidence(evidence, "rapid7_recog_ssh_banners", "recog_ssh", "ssh_banner", data.get("banner"), data)
        elif probe.probe_type == "snmp":
            _append_snmp_probe_evidence(evidence, data)
        elif probe.probe_type == "mdns":
            _append_mdns_probe_evidence(evidence, data)
        elif probe.probe_type == "upnp":
            _append_upnp_probe_evidence(evidence, data)
        elif probe.probe_type == "smb":
            _append_smb_probe_evidence(evidence, data)


def _append_http_probe_evidence(evidence: list[EvidenceItem], data: dict[str, Any]) -> None:
    _append_optional_probe_signature(evidence, "probe_http", "service", "server_header", data.get("server"), 0.80, data)
    _append_recog_evidence(evidence, "rapid7_recog_http", "recog_http", "http_server", data.get("server"), data)
    _append_optional_probe_signature(evidence, "probe_http", "identity", "http_title", data.get("title"), 0.72, data)
    _append_recog_evidence(evidence, "rapid7_recog_html_title", "recog_http_title", "html_title", data.get("title"), data)
    _append_optional_probe_signature(evidence, "probe_http", "service", "powered_by", data.get("powered_by"), 0.72, data)
    _append_optional_evidence(evidence, "probe_http", "service", "auth_header", data.get("auth_header"), 0.72, data)
    _append_recog_evidence(evidence, "rapid7_recog_http_wwwauth", "recog_http_auth", "http_auth", data.get("auth_header"), data)
    for cookie in _http_cookie_values(data):
        _append_recog_evidence(evidence, "rapid7_recog_http_cookies", "recog_http_cookie", "http_cookie", cookie, data)
    _append_optional_evidence(evidence, "probe_http", "identity", "favicon_hash", data.get("favicon_hash"), 0.76, data)
    _append_optional_probe_signature(evidence, "probe_http", "identity", "detected_app", data.get("detected_app"), 0.86, data)
    _append_optional_evidence(evidence, "probe_http", "identity", "redirect_host", data.get("redirect_host"), 0.74, data)


def _append_port_banner_recog_evidence(
    evidence: list[EvidenceItem],
    service: str | None,
    banner: str | None,
    details: dict[str, Any],
) -> None:
    if not service or not banner:
        return
    service_name = service.lower()
    recog_targets = {
        "ftp": ("rapid7_recog_ftp_banners", "recog_ftp", "ftp_banner"),
        "telnet": ("rapid7_recog_telnet_banners", "recog_telnet", "telnet_banner"),
        "smtp": ("rapid7_recog_smtp_banners", "recog_smtp", "smtp_banner"),
    }
    for token, (dataset_key, source, key_prefix) in recog_targets.items():
        if token in service_name:
            _append_recog_evidence(evidence, dataset_key, source, key_prefix, banner, details)
            return


def _append_recog_evidence(
    evidence: list[EvidenceItem],
    dataset_key: str,
    source: str,
    key_prefix: str,
    value: Any,
    data: dict[str, Any],
) -> None:
    if value is None:
        return
    match = match_recog_dataset(dataset_key, str(value))
    if match is None:
        return

    product = _recog_value(match, "service.product", "hw.product", "os.product")
    version = _recog_value(match, "service.version", "hw.version", "os.version")
    vendor = _recog_value(match, "service.vendor", "hw.vendor", "os.vendor")
    cpe = _recog_value(match, "service.cpe23", "service.cpe", "hw.cpe23", "hw.cpe", "os.cpe23", "os.cpe")
    device_type = _recog_device_type(match)
    description = _recog_value(match, "recog.description")
    details = {
        **data,
        "matched_value": str(value),
        "dataset": dataset_key,
        "product": product,
        "version": version,
        "vendor": vendor,
        "cpe": cpe,
        "device_type": device_type,
        "recog_pattern": _recog_value(match, "recog.pattern"),
        "recog_description": description,
    }

    if product:
        evidence.append(EvidenceItem(source, "service", key_prefix, product, 0.90, details))
        evidence.extend(_signature_evidence(product, source, details))
    if version:
        evidence.append(EvidenceItem(source, "service", f"{key_prefix}_version", version, 0.88, details))
    if vendor:
        evidence.append(EvidenceItem(source, "vendor", f"{key_prefix}_vendor", vendor, 0.88, details))
        evidence.extend(_signature_evidence(vendor, source, details))
    if cpe:
        evidence.append(EvidenceItem(source, "service", f"{key_prefix}_cpe", cpe, 0.88, details))
    if device_type:
        evidence.append(EvidenceItem(source, "device_type", f"{key_prefix}_device", device_type, 0.84, details))


def _recog_value(match: dict[str, str], *keys: str) -> str | None:
    for key in keys:
        value = match.get(key)
        if value:
            return value
    return None


def _recog_device_type(match: dict[str, str]) -> str | None:
    value = _recog_value(match, "hw.device", "os.device", "service.device")
    if not value:
        return None
    normalized = value.strip().lower().replace("-", " ").replace("_", " ")
    if "firewall" in normalized:
        return "firewall"
    if "switch" in normalized:
        return "switch"
    if "router" in normalized or "gateway" in normalized:
        return "router"
    if "access point" in normalized or normalized in {"ap", "wireless"}:
        return "access_point"
    if "printer" in normalized:
        return "printer"
    if "camera" in normalized or "video" in normalized or "nvr" in normalized:
        return "ip_camera"
    if "phone" in normalized or "voip" in normalized:
        return "voip"
    if "server" in normalized:
        return "server"
    if "workstation" in normalized or "desktop" in normalized or "laptop" in normalized:
        return "workstation"
    if "nas" in normalized or "storage" in normalized:
        return "nas"
    if "tv" in normalized or "media" in normalized:
        return "smart_tv"
    if "console" in normalized:
        return "game_console"
    if normalized in {"network appliance", "vpn", "embedded"}:
        return "iot_device"
    return None


def _http_cookie_values(data: dict[str, Any]) -> list[str]:
    headers = data.get("headers")
    if not isinstance(headers, dict):
        return []
    raw_cookie = headers.get("set-cookie") or headers.get("Set-Cookie") or headers.get("cookie") or headers.get("Cookie")
    if not raw_cookie:
        return []
    return [part.strip() for part in str(raw_cookie).split(",") if part.strip()]


def _append_tls_probe_evidence(evidence: list[EvidenceItem], data: dict[str, Any]) -> None:
    _append_optional_probe_signature(evidence, "probe_tls", "identity", "cert_cn", data.get("subject_cn"), 0.82, data)
    _append_optional_probe_signature(evidence, "probe_tls", "vendor", "cert_org", data.get("cert_org"), 0.84, data)
    _append_optional_evidence(evidence, "probe_tls", "identity", "cert_sha256", data.get("fingerprint_sha256"), 0.7, data)


def _append_snmp_probe_evidence(evidence: list[EvidenceItem], data: dict[str, Any]) -> None:
    _append_optional_probe_signature(evidence, "probe_snmp", "os", "sys_descr", data.get("sys_descr"), 0.92, data)
    _append_recog_evidence(evidence, "rapid7_recog_snmp_sysdescr", "recog_snmp", "snmp_sysdescr", data.get("sys_descr"), data)
    _append_optional_evidence(evidence, "probe_snmp", "identity", "sys_name", data.get("sys_name"), 0.86, data)
    sys_object_id = data.get("sys_object_id")
    _append_optional_evidence(evidence, "probe_snmp", "identity", "sys_object_id", sys_object_id, 0.90, data)
    if not sys_object_id:
        return
    pen_vendor = lookup_pen_vendor(str(sys_object_id))
    if not pen_vendor:
        return
    details = {"sys_object_id": sys_object_id}
    evidence.append(EvidenceItem("iana_pen", "vendor", "snmp_enterprise", pen_vendor, 0.83, details))
    evidence.extend(_signature_evidence(str(pen_vendor), "iana_pen", details))


def _append_mdns_probe_evidence(evidence: list[EvidenceItem], data: dict[str, Any]) -> None:
    for service in data.get("services", [])[:8]:
        service_type = service.get("type")
        _append_optional_probe_signature(evidence, "probe_mdns", "identity", "service_type", service_type, 0.78, service)
        _append_mdns_service_type_evidence(evidence, service_type, service)
        _append_optional_evidence(evidence, "probe_mdns", "identity", "service_host", service.get("host"), 0.78, service)
        _append_optional_probe_signature(evidence, "probe_mdns", "identity", "service_name", service.get("name"), 0.8, service)
        for prop_key, prop_value in (service.get("properties") or {}).items():
            if prop_value:
                _append_recog_evidence(
                    evidence,
                    "rapid7_recog_mdns_device_info",
                    "recog_mdns",
                    "mdns_device_info",
                    f"{prop_key}={prop_value}",
                    service,
                )
                evidence.extend(_signature_evidence(f"{prop_key}={prop_value}", "probe_mdns", service))


def _append_mdns_service_type_evidence(evidence: list[EvidenceItem], service_type: Any, details: dict[str, Any]) -> None:
    if not service_type:
        return
    service_text = str(service_type).lower()
    service_type_hints = [
        ("_hap._tcp", "iot_device", 0.82, "HomeKit accessory"),
        ("_hap._udp", "iot_device", 0.82, "HomeKit accessory"),
        ("_airplay._tcp", "smart_tv", 0.82, "AirPlay receiver"),
        ("_googlecast._tcp", "smart_tv", 0.84, "Google Cast device"),
        ("_ipp._tcp", "printer", 0.84, "IPP printer"),
        ("_printer._tcp", "printer", 0.82, "Printer service"),
        ("_axis-video._tcp", "ip_camera", 0.86, "Axis camera"),
        ("_sftp-ssh._tcp", "server", 0.70, "SSH file service"),
        ("_smb._tcp", "nas", 0.70, "SMB file service"),
    ]
    for token, device_type, confidence, label in service_type_hints:
        if token in service_text:
            evidence.append(
                EvidenceItem(
                    "mdns_service_type",
                    "device_type",
                    "service_type_hint",
                    device_type,
                    confidence,
                    {**details, "reason": label},
                )
            )
            return


def _append_upnp_probe_evidence(evidence: list[EvidenceItem], data: dict[str, Any]) -> None:
    _append_optional_probe_signature(evidence, "probe_upnp", "vendor", "manufacturer", data.get("manufacturer"), 0.86, data)
    _append_optional_probe_signature(evidence, "probe_upnp", "model", "model_name", data.get("model_name"), 0.88, data)
    _append_optional_probe_signature(evidence, "probe_upnp", "identity", "friendly_name", data.get("friendly_name"), 0.82, data)
    _append_optional_evidence(evidence, "probe_upnp", "identity", "device_type", data.get("device_type"), 0.8, data)


def _append_smb_probe_evidence(evidence: list[EvidenceItem], data: dict[str, Any]) -> None:
    _append_optional_probe_signature(evidence, "probe_smb", "os", "os_string", data.get("os_string"), 0.82, data)
    _append_optional_evidence(evidence, "probe_smb", "identity", "netbios_name", data.get("netbios_name"), 0.78, data)


def _append_optional_probe_signature(
    evidence: list[EvidenceItem],
    source: str,
    category: str,
    key: str,
    value: Any,
    confidence: float,
    details: dict[str, Any],
) -> None:
    if value is None:
        return
    text = str(value)
    evidence.append(EvidenceItem(source, category, key, text, confidence, details))
    evidence.extend(_signature_evidence(text, source, details))


def _append_optional_evidence(
    evidence: list[EvidenceItem],
    source: str,
    category: str,
    key: str,
    value: Any,
    confidence: float,
    details: dict[str, Any] | None = None,
) -> None:
    if value is None:
        return
    evidence.append(EvidenceItem(source, category, key, str(value), confidence, details or {}))


def derive_detected_device_type(evidence: list[EvidenceItem]) -> tuple[str | None, str]:
    candidates: dict[str, float] = {}
    best_source_for_value: dict[str, str] = {}
    max_confidence_for_value: dict[str, float] = {}
    source_count_for_value: dict[str, set[str]] = {}

    for item in evidence:
        if item.category != "device_type":
            continue
        value = item.value
        candidates[value] = candidates.get(value, 0.0) + item.confidence
        max_confidence_for_value[value] = max(max_confidence_for_value.get(value, 0.0), item.confidence)
        source_count_for_value.setdefault(value, set()).add(item.source)
        current_source = best_source_for_value.get(value)
        if current_source is None or item.confidence >= next(
            (e.confidence for e in evidence if e.category == "device_type" and e.value == value and e.source == current_source),
            -1,
        ):
            best_source_for_value[value] = item.source

    if not candidates:
        return None, "unknown"

    best_value, best_score = max(candidates.items(), key=lambda item: item[1])
    max_conf = max_confidence_for_value.get(best_value, 0.0)
    distinct_sources = len(source_count_for_value.get(best_value, set()))
    accepted = max_conf >= 0.8 or (max_conf >= 0.65 and best_score >= 1.3 and distinct_sources >= 2)

    if best_value == "unknown" or not accepted:
        return None, "unknown"

    source = best_source_for_value.get(best_value, "rule")
    if source.startswith("probe_"):
        source = "probe"
    return best_value, source
