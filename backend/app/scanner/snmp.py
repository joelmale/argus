"""
SNMP poller — queries managed devices for interface tables, ARP cache,
system info (sysDescr, sysName, sysLocation).

SNMP is like asking a device's built-in librarian for its catalog — far richer
than port-knocking alone, but requires the device to speak the protocol.
"""
from __future__ import annotations

import asyncio

from app.core.config import settings
from pysnmp.hlapi.v1arch.asyncio import (
    CommunityData as CommunityDataV1,
    ObjectIdentity as ObjectIdentityV1,
    ObjectType as ObjectTypeV1,
    SnmpDispatcher,
    UdpTransportTarget as UdpTransportTargetV1,
    get_cmd as get_cmd_v1,
    walk_cmd as walk_cmd_v1,
)
from pysnmp.hlapi.v3arch.asyncio import (
    ObjectIdentity as ObjectIdentityV3,
    ObjectType as ObjectTypeV3,
    SnmpEngine,
    UdpTransportTarget as UdpTransportTargetV3,
    UsmUserData,
    get_cmd as get_cmd_v3,
    usmAesCfb128Protocol,
    usmDESPrivProtocol,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    walk_cmd as walk_cmd_v3,
)


SYSTEM_OIDS = {
    "sys_descr": "1.3.6.1.2.1.1.1.0",
    "sys_object_id": "1.3.6.1.2.1.1.2.0",
    "sys_contact": "1.3.6.1.2.1.1.4.0",
    "sys_name": "1.3.6.1.2.1.1.5.0",
    "sys_location": "1.3.6.1.2.1.1.6.0",
}

IFACE_OIDS = {
    "name": "1.3.6.1.2.1.2.2.1.2",
    "type": "1.3.6.1.2.1.2.2.1.3",
    "speed": "1.3.6.1.2.1.2.2.1.5",
    "high_speed_mbps": "1.3.6.1.2.1.31.1.1.1.15",
    "mac": "1.3.6.1.2.1.2.2.1.6",
    "admin_status": "1.3.6.1.2.1.2.2.1.7",
    "oper_status": "1.3.6.1.2.1.2.2.1.8",
}
IFACE_COUNTER_OIDS = {
    "in_octets": "1.3.6.1.2.1.2.2.1.10",
    "in_errors": "1.3.6.1.2.1.2.2.1.14",
    "out_octets": "1.3.6.1.2.1.2.2.1.16",
    "out_errors": "1.3.6.1.2.1.2.2.1.20",
    "hc_in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "hc_out_octets": "1.3.6.1.2.1.31.1.1.1.10",
}

VLAN_PVID_OID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
ARP_MAC_OID = "1.3.6.1.2.1.4.22.1.2"
BRIDGE_FDB_PORT_OID = "1.3.6.1.2.1.17.4.3.1.2"
BRIDGE_PORT_IF_INDEX_OID = "1.3.6.1.2.1.17.1.4.1.2"
HR_PROCESSOR_LOAD_OID = "1.3.6.1.2.1.25.3.3.1.2"
HR_STORAGE_OIDS = {
    "descr": "1.3.6.1.2.1.25.2.3.1.3",
    "allocation_units": "1.3.6.1.2.1.25.2.3.1.4",
    "size": "1.3.6.1.2.1.25.2.3.1.5",
    "used": "1.3.6.1.2.1.25.2.3.1.6",
}
LLDP_OIDS = {
    "remote_chassis": "1.0.8802.1.1.2.1.4.1.1.5",
    "remote_port": "1.0.8802.1.1.2.1.4.1.1.7",
    "remote_port_desc": "1.0.8802.1.1.2.1.4.1.1.8",
    "remote_sys_name": "1.0.8802.1.1.2.1.4.1.1.9",
    "remote_sys_desc": "1.0.8802.1.1.2.1.4.1.1.10",
}
CDP_OIDS = {
    "device_id": "1.3.6.1.4.1.9.9.23.1.2.1.1.6",
    "device_port": "1.3.6.1.4.1.9.9.23.1.2.1.1.7",
    "platform": "1.3.6.1.4.1.9.9.23.1.2.1.1.8",
}


class SnmpPoller:
    def __init__(
        self,
        community: str | None = None,
        version: str | None = None,
        timeout: int | None = None,
        v3_username: str | None = None,
        v3_auth_key: str | None = None,
        v3_priv_key: str | None = None,
        v3_auth_protocol: str | None = None,
        v3_priv_protocol: str | None = None,
    ):
        self.community = community or settings.SNMP_COMMUNITY
        self.version = (version or settings.SNMP_VERSION).lower()
        self.timeout = timeout or settings.SNMP_TIMEOUT
        self.v3_username = v3_username or settings.SNMP_V3_USERNAME
        self.v3_auth_key = v3_auth_key or settings.SNMP_V3_AUTH_KEY
        self.v3_priv_key = v3_priv_key or settings.SNMP_V3_PRIV_KEY
        self.v3_auth_protocol = (v3_auth_protocol or settings.SNMP_V3_AUTH_PROTOCOL).lower()
        self.v3_priv_protocol = (v3_priv_protocol or settings.SNMP_V3_PRIV_PROTOCOL).lower()

    async def get_system_info(self, host: str) -> dict:
        """Return sysDescr, sysName, sysLocation for a host."""
        result: dict[str, str] = {}
        for key, oid in SYSTEM_OIDS.items():
            value = await self._get_single(host, oid)
            if value:
                result[key] = value
        return result

    async def get_arp_table(self, host: str) -> list[dict]:
        """Return ARP table entries: [{ip, mac}]"""
        rows = await self._walk(host, ARP_MAC_OID)
        entries: list[dict] = []
        for oid, value in rows:
            oid_parts = oid.split(".")
            if len(oid_parts) < 5:
                continue
            interface_index = int(oid_parts[-5])
            ip = ".".join(oid_parts[-4:])
            mac = _format_mac(value)
            entries.append({"ip": ip, "mac": mac, "if_index": interface_index})
        return entries

    async def get_bridge_table(self, host: str) -> list[dict]:
        """Return Bridge MIB forwarding entries: [{mac, bridge_port, if_index}]."""
        fdb_rows = await self._walk(host, BRIDGE_FDB_PORT_OID)
        port_map_rows = await self._walk(host, BRIDGE_PORT_IF_INDEX_OID)
        bridge_port_to_if_index: dict[int, int] = {}
        for oid, value in port_map_rows:
            try:
                bridge_port_to_if_index[int(oid.split(".")[-1])] = int(value)
            except (TypeError, ValueError):
                continue

        entries: list[dict] = []
        for oid, value in fdb_rows:
            mac = _format_bridge_mac_from_oid(oid)
            bridge_port = _safe_int(value)
            if mac is None or bridge_port is None:
                continue
            entries.append(
                {
                    "mac": mac,
                    "bridge_port": bridge_port,
                    "if_index": bridge_port_to_if_index.get(bridge_port),
                }
            )
        return entries

    async def get_interfaces(self, host: str) -> list[dict]:
        """Return interface table with speed, type, admin/oper state."""
        columns = {
            key: await self._walk(host, oid)
            for key, oid in {**IFACE_OIDS, **IFACE_COUNTER_OIDS}.items()
        }
        vlan_rows = await self._walk(host, VLAN_PVID_OID)

        interfaces: dict[int, dict] = {}
        for field, rows in columns.items():
            for oid, value in rows:
                if_index = int(oid.split(".")[-1])
                iface = interfaces.setdefault(if_index, {"if_index": if_index})
                iface[field] = _normalize_value(field, value)

        for oid, value in vlan_rows:
            if_index = int(oid.split(".")[-1])
            iface = interfaces.setdefault(if_index, {"if_index": if_index})
            try:
                iface["vlan_id"] = int(value)
            except (TypeError, ValueError):
                iface["vlan_id"] = None

        for iface in interfaces.values():
            iface["in_octets_total"] = iface.get("hc_in_octets")
            if iface["in_octets_total"] is None:
                iface["in_octets_total"] = iface.get("in_octets")
            iface["out_octets_total"] = iface.get("hc_out_octets")
            if iface["out_octets_total"] is None:
                iface["out_octets_total"] = iface.get("out_octets")

        return [interfaces[idx] for idx in sorted(interfaces)]

    async def get_neighbors(self, host: str) -> list[dict]:
        lldp_columns = {key: await self._walk(host, oid) for key, oid in LLDP_OIDS.items()}
        cdp_columns = {key: await self._walk(host, oid) for key, oid in CDP_OIDS.items()}
        return _parse_lldp_rows(lldp_columns) + _parse_cdp_rows(cdp_columns)

    async def get_resource_summary(self, host: str) -> dict:
        cpu_rows = await self._walk(host, HR_PROCESSOR_LOAD_OID)
        cpu_loads = [value for _, raw_value in cpu_rows if (value := _safe_int(raw_value)) is not None]

        storage_columns = {
            key: await self._walk(host, oid)
            for key, oid in HR_STORAGE_OIDS.items()
        }
        memory_summary = _extract_memory_summary(storage_columns)

        summary: dict[str, int | float | str | list[int]] = {}
        if cpu_loads:
            summary["cpu_loads"] = cpu_loads
            summary["cpu_core_count"] = len(cpu_loads)
            summary["cpu_average_load"] = round(sum(cpu_loads) / len(cpu_loads), 1)
        summary.update(memory_summary)
        return summary

    async def get_wireless_clients(self, host: str) -> list[dict]:
        # Consumer APs often expose no standard client-association tables over SNMP.
        # Keep the interface in place so vendor-specific or enterprise AP support can
        # populate this later without changing the pipeline contract.
        if not host:
            return []
        await asyncio.sleep(0)
        return []

    async def _get_single(self, host: str, oid: str) -> str | None:
        if self.version == "3":
            engine = SnmpEngine()
            auth = self._v3_auth()
            transport = await UdpTransportTargetV3.create((host, 161), timeout=self.timeout, retries=1)
            error_indication, error_status, _, var_binds = await get_cmd_v3(
                engine,
                auth,
                transport,
                ObjectTypeV3(ObjectIdentityV3(oid)),
            )
        else:
            dispatcher = SnmpDispatcher()
            auth = CommunityDataV1(self.community, mpModel=1)
            transport = await UdpTransportTargetV1.create((host, 161), timeout=self.timeout, retries=1)
            error_indication, error_status, _, var_binds = await get_cmd_v1(
                dispatcher,
                auth,
                transport,
                ObjectTypeV1(ObjectIdentityV1(oid)),
            )

        if error_indication or error_status:
            return None
        return str(var_binds[0][1]) if var_binds else None

    async def _walk(self, host: str, oid: str) -> list[tuple[str, str]]:
        rows: list[tuple[str, str]] = []

        if self.version == "3":
            engine = SnmpEngine()
            auth = self._v3_auth()
            transport = await UdpTransportTargetV3.create((host, 161), timeout=self.timeout, retries=1)
            walker = walk_cmd_v3(
                engine,
                auth,
                transport,
                ObjectTypeV3(ObjectIdentityV3(oid)),
            )
        else:
            dispatcher = SnmpDispatcher()
            auth = CommunityDataV1(self.community, mpModel=1)
            transport = await UdpTransportTargetV1.create((host, 161), timeout=self.timeout, retries=1)
            walker = walk_cmd_v1(
                dispatcher,
                auth,
                transport,
                ObjectTypeV1(ObjectIdentityV1(oid)),
            )

        async for error_indication, error_status, _, var_binds in walker:
            if error_indication or error_status:
                break
            for var_bind in var_binds:
                rows.append((str(var_bind[0]), str(var_bind[1])))

        return rows

    def _v3_auth(self) -> UsmUserData:
        auth_protocol = usmHMACSHAAuthProtocol if self.v3_auth_protocol == "sha" else usmHMACMD5AuthProtocol
        priv_protocol = usmAesCfb128Protocol if self.v3_priv_protocol == "aes" else usmDESPrivProtocol
        return UsmUserData(
            userName=self.v3_username,
            authKey=self.v3_auth_key,
            privKey=self.v3_priv_key,
            authProtocol=auth_protocol,
            privProtocol=priv_protocol,
        )


def _format_mac(value: str) -> str:
    value = value.replace("0x", "").replace(":", "").replace("-", "")
    if len(value) % 2 != 0:
        return value.upper()
    return ":".join(value[i : i + 2] for i in range(0, len(value), 2)).upper()


def _format_bridge_mac_from_oid(oid: str) -> str | None:
    parts = oid.split(".")
    if len(parts) < 6:
        return None
    try:
        octets = [int(part) for part in parts[-6:]]
    except ValueError:
        return None
    if any(octet < 0 or octet > 255 for octet in octets):
        return None
    return ":".join(f"{octet:02X}" for octet in octets)


def _normalize_value(field: str, value: str):
    if field in {
        "type",
        "speed",
        "high_speed_mbps",
        "admin_status",
        "oper_status",
        "in_octets",
        "out_octets",
        "in_errors",
        "out_errors",
        "hc_in_octets",
        "hc_out_octets",
    }:
        try:
            return int(value)
        except ValueError:
            return value
    if field == "mac":
        return _format_mac(value)
    return value


def _safe_int(value: str | int | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _extract_memory_summary(columns: dict[str, list[tuple[str, str]]]) -> dict[str, int | float | str]:
    rows: dict[int, dict[str, str | int]] = {}
    for field, entries in columns.items():
        for oid, value in entries:
            try:
                storage_index = int(oid.split(".")[-1])
            except ValueError:
                continue
            row = rows.setdefault(storage_index, {"index": storage_index})
            if field == "descr":
                row[field] = value
            else:
                parsed_value = _safe_int(value)
                if parsed_value is not None:
                    row[field] = parsed_value

    ranked_entries: list[tuple[int, int, str, int, int]] = []
    for row in rows.values():
        descr = str(row.get("descr") or "").strip()
        if not descr:
            continue
        allocation_units = _safe_int(row.get("allocation_units"))
        size = _safe_int(row.get("size"))
        used = _safe_int(row.get("used"))
        if not allocation_units or size is None or used is None or size <= 0:
            continue
        rank = _memory_rank(descr)
        if rank == 0:
            continue
        total_bytes = allocation_units * size
        used_bytes = allocation_units * used
        ranked_entries.append((rank, total_bytes, descr, total_bytes, used_bytes))

    if not ranked_entries:
        return {}

    _, _, descr, total_bytes, used_bytes = max(ranked_entries, key=lambda item: (item[0], item[1]))
    utilization = round(used_bytes / total_bytes, 4) if total_bytes > 0 else None
    summary: dict[str, int | float | str] = {
        "memory_label": descr,
        "memory_total_bytes": total_bytes,
        "memory_used_bytes": used_bytes,
    }
    if utilization is not None:
        summary["memory_utilization"] = utilization
    return summary


def _memory_rank(description: str) -> int:
    normalized = description.lower()
    if "physical memory" in normalized:
        return 4
    if normalized.startswith("memory") or normalized.endswith(" memory"):
        return 3
    if "memory" in normalized:
        return 2
    if "ram" in normalized:
        return 1
    return 0


def _parse_lldp_rows(columns: dict[str, list[tuple[str, str]]]) -> list[dict]:
    rows: dict[tuple[int, int], dict] = {}
    for field, entries in columns.items():
        for oid, value in entries:
            parts = oid.split(".")
            if len(parts) < 3:
                continue
            try:
                local_port = int(parts[-2])
                remote_index = int(parts[-1])
            except ValueError:
                continue
            row = rows.setdefault((local_port, remote_index), {"protocol": "lldp", "local_port": local_port})
            row[field] = value

    neighbors: list[dict] = []
    for row in rows.values():
        neighbors.append(
            {
                "protocol": "lldp",
                "local_port": row.get("local_port"),
                "remote_name": row.get("remote_sys_name"),
                "remote_port": row.get("remote_port_desc") or row.get("remote_port"),
                "remote_mac": _format_mac(row["remote_chassis"]) if row.get("remote_chassis") else None,
                "remote_platform": row.get("remote_sys_desc"),
            }
        )
    return neighbors


def _parse_cdp_rows(columns: dict[str, list[tuple[str, str]]]) -> list[dict]:
    rows: dict[tuple[int, int], dict] = {}
    for field, entries in columns.items():
        for oid, value in entries:
            parts = oid.split(".")
            if len(parts) < 2:
                continue
            try:
                local_port = int(parts[-2])
                remote_index = int(parts[-1])
            except ValueError:
                continue
            row = rows.setdefault((local_port, remote_index), {"protocol": "cdp", "local_port": local_port})
            row[field] = value

    neighbors: list[dict] = []
    for row in rows.values():
        neighbors.append(
            {
                "protocol": "cdp",
                "local_port": row.get("local_port"),
                "remote_name": row.get("device_id"),
                "remote_port": row.get("device_port"),
                "remote_platform": row.get("platform"),
                "remote_mac": None,
            }
        )
    return neighbors
