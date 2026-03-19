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
    host_nodes = root.findall("host")
    if target_ip:
        filtered: list[ET.Element] = []
        for host in host_nodes:
            for address in host.findall("address"):
                if address.get("addrtype") == "ipv4" and address.get("addr") == target_ip:
                    filtered.append(host)
                    break
        host_nodes = filtered
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
    service_map = {port.port: ((port.service or "").lower(), (port.version or "").lower(), (port.product or "").lower()) for port in ports}
    cpes = " ".join(os_fingerprint.cpe).lower()
    os_name_lower = (os_fingerprint.os_name or "").lower()

    if "firewalla" in vendor_lower or "firewalla" in hostname_lower:
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

    if 53 in service_map:
        service, version, product = service_map[53]
        if service == "domain" and "dnsmasq" in f"{version} {product}" and ("netgate" in vendor_lower or "pfsense" in hostname_lower):
            return InstantWinFingerprint(
                vendor=mac_vendor,
                device_type="firewall",
                os_name=os_fingerprint.os_name or "FreeBSD/pfSense appliance",
                os_family=os_fingerprint.os_family or "BSD",
                os_version=os_fingerprint.os_version,
                confidence=0.92,
                reason="dnsmasq + Netgate/pfSense identity",
            )

    if "mikrotik" in vendor_lower or "mikrotik" in cpes:
        return InstantWinFingerprint(
            vendor="MikroTik",
            device_type="router",
            os_name="MikroTik RouterOS",
            os_family="Linux",
            os_version=os_fingerprint.os_version,
            confidence=0.94,
            reason="Matched MikroTik vendor/CPE",
        )

    return None


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
    addresses = host_node.findall("address")
    for address in addresses:
        addr = address.get("addr")
        addr_type = address.get("addrtype")
        vendor = address.get("vendor")
        if addr_type == "mac" and addr:
            if vendor:
                host_data["vendor"][addr] = vendor

    for hostname in host_node.findall("./hostnames/hostname"):
        name = hostname.get("name")
        if name:
            host_data["hostnames"].append({"name": name, "type": hostname.get("type") or ""})

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

    host_data["osmatch"] = []
    for match in host_node.findall("./os/osmatch"):
        osclass_entries: list[dict[str, Any]] = []
        for osclass in match.findall("osclass"):
            cpe_values = [cpe.text for cpe in osclass.findall("cpe") if cpe.text]
            osclass_entries.append(
                {
                    "osfamily": osclass.get("osfamily"),
                    "osgen": osclass.get("osgen"),
                    "type": osclass.get("type"),
                    "cpe": cpe_values,
                }
            )
        host_data["osmatch"].append(
            {
                "name": match.get("name"),
                "accuracy": match.get("accuracy", "0"),
                "osclass": osclass_entries,
            }
        )
    return host_data
