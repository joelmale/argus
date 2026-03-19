from app.scanner.stages.discovery import _parse_ping_sweep_xml


def test_parse_ping_sweep_xml_only_returns_up_hosts():
    xml = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="arp-response" reason_ttl="64"/>
    <address addr="192.168.100.1" addrtype="ipv4"/>
    <address addr="20:6D:31:41:56:2A" addrtype="mac"/>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.100.2" addrtype="ipv4"/>
  </host>
</nmaprun>
"""
    hosts = _parse_ping_sweep_xml(xml)
    assert len(hosts) == 1
    assert hosts[0].ip_address == "192.168.100.1"
    assert hosts[0].mac_address == "20:6D:31:41:56:2A"
    assert hosts[0].ttl == 64
