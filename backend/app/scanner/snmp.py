"""
SNMP poller — queries managed devices for interface tables, ARP cache,
system info (sysDescr, sysName, sysLocation).

SNMP is like asking a device's built-in librarian for its catalog — far richer
than port-knocking alone, but requires the device to speak the protocol.
"""
from __future__ import annotations

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
    "mac": "1.3.6.1.2.1.2.2.1.6",
    "admin_status": "1.3.6.1.2.1.2.2.1.7",
    "oper_status": "1.3.6.1.2.1.2.2.1.8",
}

VLAN_PVID_OID = "1.3.6.1.2.1.17.7.1.4.5.1.1"
ARP_MAC_OID = "1.3.6.1.2.1.4.22.1.2"


class SnmpPoller:
    def __init__(self, community: str | None = None, version: str | None = None):
        self.community = community or settings.SNMP_COMMUNITY
        self.version = (version or settings.SNMP_VERSION).lower()

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

    async def get_interfaces(self, host: str) -> list[dict]:
        """Return interface table with speed, type, admin/oper state."""
        columns = {
            key: await self._walk(host, oid)
            for key, oid in IFACE_OIDS.items()
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

        return [interfaces[idx] for idx in sorted(interfaces)]

    async def _get_single(self, host: str, oid: str) -> str | None:
        if self.version == "3":
            engine = SnmpEngine()
            auth = self._v3_auth()
            transport = await UdpTransportTargetV3.create((host, 161), timeout=settings.SNMP_TIMEOUT, retries=1)
            error_indication, error_status, _, var_binds = await get_cmd_v3(
                engine,
                auth,
                transport,
                ObjectTypeV3(ObjectIdentityV3(oid)),
            )
        else:
            dispatcher = SnmpDispatcher()
            auth = CommunityDataV1(self.community, mpModel=1)
            transport = await UdpTransportTargetV1.create((host, 161), timeout=settings.SNMP_TIMEOUT, retries=1)
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
            transport = await UdpTransportTargetV3.create((host, 161), timeout=settings.SNMP_TIMEOUT, retries=1)
            walker = walk_cmd_v3(
                engine,
                auth,
                transport,
                ObjectTypeV3(ObjectIdentityV3(oid)),
            )
        else:
            dispatcher = SnmpDispatcher()
            auth = CommunityDataV1(self.community, mpModel=1)
            transport = await UdpTransportTargetV1.create((host, 161), timeout=settings.SNMP_TIMEOUT, retries=1)
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
        auth_protocol = usmHMACSHAAuthProtocol if settings.SNMP_V3_AUTH_PROTOCOL.lower() == "sha" else usmHMACMD5AuthProtocol
        priv_protocol = usmAesCfb128Protocol if settings.SNMP_V3_PRIV_PROTOCOL.lower() == "aes" else usmDESPrivProtocol
        return UsmUserData(
            userName=settings.SNMP_V3_USERNAME,
            authKey=settings.SNMP_V3_AUTH_KEY,
            privKey=settings.SNMP_V3_PRIV_KEY,
            authProtocol=auth_protocol,
            privProtocol=priv_protocol,
        )


def _format_mac(value: str) -> str:
    value = value.replace("0x", "").replace(":", "").replace("-", "")
    if len(value) % 2 != 0:
        return value.upper()
    return ":".join(value[i : i + 2] for i in range(0, len(value), 2)).upper()


def _normalize_value(field: str, value: str):
    if field in {"type", "speed", "admin_status", "oper_status"}:
        try:
            return int(value)
        except ValueError:
            return value
    if field == "mac":
        return _format_mac(value)
    return value
