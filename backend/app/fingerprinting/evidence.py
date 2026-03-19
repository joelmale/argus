from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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


def extract_evidence(result: HostScanResult) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = []

    if result.mac_vendor:
        evidence.append(EvidenceItem("mac_oui", "vendor", "mac_vendor", result.mac_vendor, 0.72, {}))

    if result.host.ttl is not None:
        evidence.append(
            EvidenceItem(
                "tcpip_stack",
                "os_hint",
                "ttl",
                str(result.host.ttl),
                0.30,
                {"ttl": result.host.ttl},
            )
        )

    if result.os_fingerprint.os_name and result.os_fingerprint.os_accuracy:
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

    if result.reverse_hostname:
        evidence.append(
            EvidenceItem("hostname", "identity", "hostname", result.reverse_hostname, 0.60, {})
        )

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

    rule_hint = classify(result.host, result.ports, result.os_fingerprint, result.mac_vendor)
    if rule_hint.device_class.value != "unknown":
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

    ai = result.ai_analysis
    if ai is not None:
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
        if ai.vendor:
            evidence.append(EvidenceItem("ai", "vendor", "vendor", ai.vendor, ai.confidence, {}))
        if ai.model:
            evidence.append(EvidenceItem("ai", "model", "model", ai.model, ai.confidence, {}))
        if ai.os_guess:
            evidence.append(EvidenceItem("ai", "os", "os_guess", ai.os_guess, ai.confidence, {}))

    for probe in result.probes:
        if not probe.success:
            continue
        data = probe.data or {}
        if probe.probe_type == "http":
            if data.get("server"):
                evidence.append(EvidenceItem("probe_http", "service", "server_header", str(data["server"]), 0.80, data))
            if data.get("title"):
                evidence.append(EvidenceItem("probe_http", "identity", "http_title", str(data["title"]), 0.72, data))
            if data.get("powered_by"):
                evidence.append(EvidenceItem("probe_http", "service", "powered_by", str(data["powered_by"]), 0.72, data))
        elif probe.probe_type == "tls":
            if data.get("subject_cn"):
                evidence.append(EvidenceItem("probe_tls", "identity", "cert_cn", str(data["subject_cn"]), 0.82, data))
            if data.get("cert_org"):
                evidence.append(EvidenceItem("probe_tls", "vendor", "cert_org", str(data["cert_org"]), 0.84, data))
        elif probe.probe_type == "ssh":
            if data.get("banner"):
                evidence.append(EvidenceItem("probe_ssh", "service", "ssh_banner", str(data["banner"]), 0.80, data))
        elif probe.probe_type == "snmp":
            if data.get("sys_descr"):
                evidence.append(EvidenceItem("probe_snmp", "os", "sys_descr", str(data["sys_descr"]), 0.92, data))
            if data.get("sys_name"):
                evidence.append(EvidenceItem("probe_snmp", "identity", "sys_name", str(data["sys_name"]), 0.86, data))
            if data.get("sys_object_id"):
                evidence.append(EvidenceItem("probe_snmp", "identity", "sys_object_id", str(data["sys_object_id"]), 0.90, data))
        elif probe.probe_type == "mdns":
            for service in data.get("services", [])[:8]:
                if service.get("type"):
                    evidence.append(
                        EvidenceItem("probe_mdns", "identity", "service_type", str(service["type"]), 0.78, service)
                    )
                if service.get("host"):
                    evidence.append(
                        EvidenceItem("probe_mdns", "identity", "service_host", str(service["host"]), 0.78, service)
                    )
        elif probe.probe_type == "upnp":
            if data.get("manufacturer"):
                evidence.append(EvidenceItem("probe_upnp", "vendor", "manufacturer", str(data["manufacturer"]), 0.86, data))
            if data.get("model_name"):
                evidence.append(EvidenceItem("probe_upnp", "model", "model_name", str(data["model_name"]), 0.88, data))
            if data.get("friendly_name"):
                evidence.append(EvidenceItem("probe_upnp", "identity", "friendly_name", str(data["friendly_name"]), 0.82, data))
        elif probe.probe_type == "smb":
            if data.get("os_string"):
                evidence.append(EvidenceItem("probe_smb", "os", "os_string", str(data["os_string"]), 0.82, data))
            if data.get("netbios_name"):
                evidence.append(EvidenceItem("probe_smb", "identity", "netbios_name", str(data["netbios_name"]), 0.78, data))

    return evidence


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
