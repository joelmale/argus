from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from xml.etree import ElementTree as ET

from app.scanner.models import OSFingerprint, PortResult


@dataclass(slots=True)
class InstantWinFingerprint:
    vendor: str | None = None
    device_type: str | None = None
    os_name: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    confidence: float = 0.0
    reason: str | None = None


def fingerprint_from_nmap_xml(xml_output: str, target_ip: str | None = None) -> InstantWinFingerprint | None:
    root = ET.fromstring(xml_output)
    host_nodes = _select_host_nodes(root.findall("host"), target_ip)
    if not host_nodes:
        return None
    return fingerprint_from_nmap_host_data(_host_xml_to_dict(host_nodes[0]))


def fingerprint_from_nmap_host_data(host_data: dict[str, Any]) -> InstantWinFingerprint | None:
    mac_vendor = _extract_vendor(host_data)
    hostname = _extract_hostname(host_data)
    ports = _extract_ports(host_data)
    os_fp = _extract_os(host_data)
    return fingerprint_from_signals(
        mac_vendor=mac_vendor,
        hostname=hostname,
        ports=ports,
        os_fingerprint=os_fp,
    )


def fingerprint_from_signals(
    *,
    mac_vendor: str | None,
    hostname: str | None,
    ports: list[PortResult],
    os_fingerprint: OSFingerprint,
) -> InstantWinFingerprint | None:
    vendor_lower = (mac_vendor or "").lower()
    hostname_lower = (hostname or "").lower()
    service_map = _build_service_map(ports)
    cpes = " ".join(os_fingerprint.cpe).lower()
    os_name_lower = (os_fingerprint.os_name or "").lower()

    return (
        _match_firewalla(vendor_lower, hostname_lower, service_map, os_fingerprint, os_name_lower)
        or _match_pfsense(vendor_lower, hostname_lower, service_map, mac_vendor, os_fingerprint)
        or _match_mikrotik(vendor_lower, cpes, os_fingerprint)
    )


def merge_into_os_fingerprint(os_fingerprint: OSFingerprint, instant: InstantWinFingerprint | None) -> OSFingerprint:
    if instant is None:
        return os_fingerprint
    return OSFingerprint(
        os_name=instant.os_name or os_fingerprint.os_name,
        os_family=instant.os_family or os_fingerprint.os_family,
        os_version=instant.os_version or os_fingerprint.os_version,
        os_accuracy=max(os_fingerprint.os_accuracy or 0, int(instant.confidence * 100)),
        device_type=instant.device_type or os_fingerprint.device_type,
        cpe=os_fingerprint.cpe,
    )


def _extract_vendor(host_data: dict[str, Any]) -> str | None:
    vendor_data = host_data.get("vendor", {})
    if isinstance(vendor_data, dict):
        for value in vendor_data.values():
            if value:
                return str(value)
    return None


def _extract_hostname(host_data: dict[str, Any]) -> str | None:
    for entry in host_data.get("hostnames", []):
        name = entry.get("name")
        if name:
            return str(name)
    return None


def _extract_ports(host_data: dict[str, Any]) -> list[PortResult]:
    ports: list[PortResult] = []
    for proto in ("tcp", "udp"):
        for port_num, info in host_data.get(proto, {}).items():
            if info.get("state") != "open":
                continue
            parts = [info.get("product", ""), info.get("version", ""), info.get("extrainfo", "")]
            version_str = " ".join(p for p in parts if p).strip() or None
            ports.append(
                PortResult(
                    port=int(port_num),
                    protocol=proto,
                    state="open",
                    service=info.get("name"),
                    version=version_str,
                    product=info.get("product"),
                    extra_info=info.get("extrainfo"),
                )
            )
    return ports


def _extract_os(host_data: dict[str, Any]) -> OSFingerprint:
    os_matches = host_data.get("osmatch", [])
    if not os_matches:
        return OSFingerprint()
    best = os_matches[0]
    osclass = best.get("osclass", [{}])[0] if best.get("osclass") else {}
    cpes: list[str] = []
    for entry in best.get("osclass", []):
        value = entry.get("cpe")
        if isinstance(value, list):
            cpes.extend([item for item in value if isinstance(item, str)])
        elif isinstance(value, str):
            cpes.append(value)
    return OSFingerprint(
        os_name=best.get("name"),
        os_family=osclass.get("osfamily"),
        os_version=osclass.get("osgen"),
        os_accuracy=int(best.get("accuracy", 0)),
        device_type=osclass.get("type"),
        cpe=cpes,
    )


def _host_xml_to_dict(host_node: ET.Element) -> dict[str, Any]:
    host_data: dict[str, Any] = {"tcp": {}, "udp": {}, "hostnames": [], "vendor": {}}
    host_data["vendor"] = _extract_vendor_map(host_node)
    host_data["hostnames"] = _extract_hostname_entries(host_node)
    _populate_port_entries(host_node, host_data)
    host_data["osmatch"] = _extract_osmatch_entries(host_node)
    return host_data


def _select_host_nodes(host_nodes: list[ET.Element], target_ip: str | None) -> list[ET.Element]:
    if not target_ip:
        return host_nodes
    return [host for host in host_nodes if _host_matches_ip(host, target_ip)]


def _host_matches_ip(host_node: ET.Element, target_ip: str) -> bool:
    for address in host_node.findall("address"):
        if address.get("addrtype") == "ipv4" and address.get("addr") == target_ip:
            return True
    return False


def _build_service_map(ports: list[PortResult]) -> dict[int, tuple[str, str, str]]:
    return {
        port.port: ((port.service or "").lower(), (port.version or "").lower(), (port.product or "").lower())
        for port in ports
    }


def _match_firewalla(
    vendor_lower: str,
    hostname_lower: str,
    service_map: dict[int, tuple[str, str, str]],
    os_fingerprint: OSFingerprint,
    os_name_lower: str,
) -> InstantWinFingerprint | None:
    if "firewalla" not in vendor_lower and "firewalla" not in hostname_lower:
        return None
    ssh_version = service_map.get(22, ("", "", ""))[1]
    os_version = "22.04" if "3ubuntu0." in ssh_version else (os_fingerprint.os_version or None)
    return InstantWinFingerprint(
        vendor="Firewalla",
        device_type="firewall",
        os_name="Ubuntu Linux" if "ubuntu" in ssh_version or "linux" in os_name_lower else (os_fingerprint.os_name or "Linux"),
        os_family="Linux",
        os_version=os_version,
        confidence=0.99,
        reason="Matched Firewalla MAC/hostname with router/firewall service pattern",
    )


def _match_pfsense(
    vendor_lower: str,
    hostname_lower: str,
    service_map: dict[int, tuple[str, str, str]],
    mac_vendor: str | None,
    os_fingerprint: OSFingerprint,
) -> InstantWinFingerprint | None:
    if 53 not in service_map:
        return None
    service, version, product = service_map[53]
    if service != "domain" or "dnsmasq" not in f"{version} {product}":
        return None
    if "netgate" not in vendor_lower and "pfsense" not in hostname_lower:
        return None
    return InstantWinFingerprint(
        vendor=mac_vendor,
        device_type="firewall",
        os_name=os_fingerprint.os_name or "FreeBSD/pfSense appliance",
        os_family=os_fingerprint.os_family or "BSD",
        os_version=os_fingerprint.os_version,
        confidence=0.92,
        reason="dnsmasq + Netgate/pfSense identity",
    )


def _match_mikrotik(vendor_lower: str, cpes: str, os_fingerprint: OSFingerprint) -> InstantWinFingerprint | None:
    if "mikrotik" not in vendor_lower and "mikrotik" not in cpes:
        return None
    return InstantWinFingerprint(
        vendor="MikroTik",
        device_type="router",
        os_name="MikroTik RouterOS",
        os_family="Linux",
        os_version=os_fingerprint.os_version,
        confidence=0.94,
        reason="Matched MikroTik vendor/CPE",
    )


def _extract_vendor_map(host_node: ET.Element) -> dict[str, str]:
    vendor_map: dict[str, str] = {}
    for address in host_node.findall("address"):
        addr = address.get("addr")
        vendor = address.get("vendor")
        if address.get("addrtype") == "mac" and addr and vendor:
            vendor_map[addr] = vendor
    return vendor_map


def _extract_hostname_entries(host_node: ET.Element) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    for hostname in host_node.findall("./hostnames/hostname"):
        name = hostname.get("name")
        if name:
            entries.append({"name": name, "type": hostname.get("type") or ""})
    return entries


def _populate_port_entries(host_node: ET.Element, host_data: dict[str, Any]) -> None:
    for port in host_node.findall("./ports/port"):
        proto = port.get("protocol", "tcp")
        portid = int(port.get("portid", "0"))
        state = port.find("state")
        service = port.find("service")
        host_data.setdefault(proto, {})[portid] = {
            "state": state.get("state") if state is not None else "closed",
            "name": service.get("name") if service is not None else None,
            "product": service.get("product") if service is not None else None,
            "version": service.get("version") if service is not None else None,
            "extrainfo": service.get("extrainfo") if service is not None else None,
        }


def _extract_osmatch_entries(host_node: ET.Element) -> list[dict[str, Any]]:
    return [_build_osmatch_entry(match) for match in host_node.findall("./os/osmatch")]


def _build_osmatch_entry(match: ET.Element) -> dict[str, Any]:
    return {
        "name": match.get("name"),
        "accuracy": match.get("accuracy", "0"),
        "osclass": [_build_osclass_entry(osclass) for osclass in match.findall("osclass")],
    }


def _build_osclass_entry(osclass: ET.Element) -> dict[str, Any]:
    cpe_values = [cpe.text for cpe in osclass.findall("cpe") if cpe.text]
    return {
        "osfamily": osclass.get("osfamily"),
        "osgen": osclass.get("osgen"),
        "type": osclass.get("type"),
        "cpe": cpe_values,
    }
