"""
SNMP poller — queries managed devices for interface tables, ARP cache,
system info (sysDescr, sysName, sysLocation).

SNMP is like asking a device's built-in librarian for its catalog — far richer
than port-knocking alone, but requires the device to speak the protocol.
"""
# TODO: implement pysnmp async walker
# Key OIDs:
#   sysDescr     1.3.6.1.2.1.1.1.0
#   sysName      1.3.6.1.2.1.1.5.0
#   ifTable      1.3.6.1.2.1.2.2
#   ipNetToMedia 1.3.6.1.2.1.4.22  (ARP table)

from app.core.config import settings


class SnmpPoller:
    def __init__(self, community: str | None = None):
        self.community = community or settings.SNMP_COMMUNITY

    async def get_system_info(self, host: str) -> dict:
        """Return sysDescr, sysName, sysLocation for a host."""
        raise NotImplementedError("SNMP poller — Phase 2")

    async def get_arp_table(self, host: str) -> list[dict]:
        """Return ARP table entries: [{ip, mac}]"""
        raise NotImplementedError("SNMP poller — Phase 2")

    async def get_interfaces(self, host: str) -> list[dict]:
        """Return interface table with speed, type, admin/oper state."""
        raise NotImplementedError("SNMP poller — Phase 2")
