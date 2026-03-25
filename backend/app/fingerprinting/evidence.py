from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.fingerprinting.datasets import lookup_pen_vendor
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
    evidence.extend(_signature_evidence(reverse_hostname, "hostname", details))


def _append_port_evidence(evidence: list[EvidenceItem], result: HostScanResult) -> None:
    for port in result.open_ports:
        evidence.append(
            EvidenceItem(
                "nmap_service",
                "service",
                f"{port.port}/{port.protocol}",
                port.service or "unknown",
                0.75,
                {
                    "port": port.port,
                    "protocol": port.protocol,
                    "product": port.product,
                    "version": port.version,
                    "cpe": port.cpe,
                },
            )
        )


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
    _append_optional_probe_signature(evidence, "probe_http", "identity", "http_title", data.get("title"), 0.72, data)
    _append_optional_probe_signature(evidence, "probe_http", "service", "powered_by", data.get("powered_by"), 0.72, data)
    _append_optional_evidence(evidence, "probe_http", "service", "auth_header", data.get("auth_header"), 0.72, data)
    _append_optional_evidence(evidence, "probe_http", "identity", "favicon_hash", data.get("favicon_hash"), 0.76, data)
    _append_optional_probe_signature(evidence, "probe_http", "identity", "detected_app", data.get("detected_app"), 0.86, data)
    _append_optional_evidence(evidence, "probe_http", "identity", "redirect_host", data.get("redirect_host"), 0.74, data)


def _append_tls_probe_evidence(evidence: list[EvidenceItem], data: dict[str, Any]) -> None:
    _append_optional_probe_signature(evidence, "probe_tls", "identity", "cert_cn", data.get("subject_cn"), 0.82, data)
    _append_optional_probe_signature(evidence, "probe_tls", "vendor", "cert_org", data.get("cert_org"), 0.84, data)
    _append_optional_evidence(evidence, "probe_tls", "identity", "cert_sha256", data.get("fingerprint_sha256"), 0.7, data)


def _append_snmp_probe_evidence(evidence: list[EvidenceItem], data: dict[str, Any]) -> None:
    _append_optional_probe_signature(evidence, "probe_snmp", "os", "sys_descr", data.get("sys_descr"), 0.92, data)
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
        _append_optional_probe_signature(evidence, "probe_mdns", "identity", "service_type", service.get("type"), 0.78, service)
        _append_optional_evidence(evidence, "probe_mdns", "identity", "service_host", service.get("host"), 0.78, service)
        _append_optional_probe_signature(evidence, "probe_mdns", "identity", "service_name", service.get("name"), 0.8, service)
        for prop_key, prop_value in (service.get("properties") or {}).items():
            if prop_value:
                evidence.extend(_signature_evidence(f"{prop_key}={prop_value}", "probe_mdns", service))


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
