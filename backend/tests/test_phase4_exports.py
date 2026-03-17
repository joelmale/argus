from datetime import datetime, timezone
from uuid import uuid4

from app.db.models import Asset, AssetTag
from app.exporters import render_ansible_inventory, render_terraform_inventory


def _asset(ip: str, *, hostname: str | None, device_type: str | None, status: str, tags: list[str]) -> Asset:
    asset = Asset(
        id=uuid4(),
        ip_address=ip,
        hostname=hostname,
        device_type=device_type,
        vendor="TestVendor",
        status=status,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    asset.tags = [AssetTag(tag=tag) for tag in tags]
    asset.ports = []
    return asset


def test_render_ansible_inventory_groups_assets():
    assets = [
        _asset("192.168.1.10", hostname="core-sw", device_type="switch", status="online", tags=["infra"]),
        _asset("192.168.1.20", hostname="nas-01", device_type="nas", status="offline", tags=["storage"]),
    ]

    inventory = render_ansible_inventory(assets)

    assert "[argus]" in inventory
    assert "[switch]" in inventory
    assert "[offline]" in inventory
    assert "[tag_storage]" in inventory
    assert "core-sw ansible_host=192.168.1.10" in inventory


def test_render_terraform_inventory_uses_terraform_data_resources():
    assets = [_asset("192.168.1.10", hostname="core-sw", device_type="switch", status="online", tags=["infra"])]

    rendered = render_terraform_inventory(assets)

    assert '"terraform_data"' in rendered
    assert '"ip_address": "192.168.1.10"' in rendered
    assert '"argus_asset_count"' in rendered
