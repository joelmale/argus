from app.modules.tplink_deco import _md5_hex, normalize_deco_client


def test_tplink_password_hash_matches_expected_md5():
    assert _md5_hex("adminsupersecret") == "db5107e4dc566c9fc001bb0e404fce0c"


def test_normalize_deco_client_maps_common_field_names():
    record = normalize_deco_client(
        {
            "mac": "20-6d-31-41-56-2a",
            "ip_addr": "192.168.100.25",
            "name": "joels-macbook",
            "nickname": "Joel MacBook",
            "device_model": "MacBook Pro",
            "interface": "wireless",
            "master_device_name": "Deco Office",
        }
    )

    assert record.mac == "20:6D:31:41:56:2A"
    assert record.ip == "192.168.100.25"
    assert record.hostname == "joels-macbook"
    assert record.nickname == "Joel MacBook"
    assert record.device_model == "MacBook Pro"
    assert record.connection_type == "wireless"
    assert record.access_point_name == "Deco Office"
