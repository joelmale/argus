from app.scanner.snmp import _parse_cdp_rows, _parse_lldp_rows


def test_parse_lldp_rows_extracts_remote_neighbors():
    rows = _parse_lldp_rows(
        {
            "remote_sys_name": [("1.0.8802.1.1.2.1.4.1.1.9.10.7.1", "switch-core")],
            "remote_port_desc": [("1.0.8802.1.1.2.1.4.1.1.8.10.7.1", "Gi0/1")],
            "remote_chassis": [("1.0.8802.1.1.2.1.4.1.1.5.10.7.1", "AABBCCDDEEFF")],
            "remote_sys_desc": [("1.0.8802.1.1.2.1.4.1.1.10.10.7.1", "SwitchOS")],
            "remote_port": [],
        }
    )

    assert rows == [
        {
            "protocol": "lldp",
            "local_port": 7,
            "remote_name": "switch-core",
            "remote_port": "Gi0/1",
            "remote_mac": "AA:BB:CC:DD:EE:FF",
            "remote_platform": "SwitchOS",
        }
    ]


def test_parse_cdp_rows_extracts_remote_neighbors():
    rows = _parse_cdp_rows(
        {
            "device_id": [("1.3.6.1.4.1.9.9.23.1.2.1.1.6.12.1", "edge-router")],
            "device_port": [("1.3.6.1.4.1.9.9.23.1.2.1.1.7.12.1", "Gi0/0")],
            "platform": [("1.3.6.1.4.1.9.9.23.1.2.1.1.8.12.1", "Cisco IOS XE")],
        }
    )

    assert rows == [
        {
            "protocol": "cdp",
            "local_port": 12,
            "remote_name": "edge-router",
            "remote_port": "Gi0/0",
            "remote_platform": "Cisco IOS XE",
            "remote_mac": None,
        }
    ]
