from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.db.models import Asset, AssetTag, Port
from app.exporters import build_inventory_snapshot
from app.integrations import build_home_assistant_entities, list_integration_events


@pytest.mark.asyncio
async def test_inventory_and_home_assistant_exports_include_asset_details():
    asset = Asset(
        id=uuid4(),
        ip_address="192.168.50.10",
        hostname="mesh-ap-1",
        mac_address="AA:BB:CC:DD:EE:01",
        vendor="TP-Link",
        device_type="access_point",
        status="online",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    asset.tags = [AssetTag(tag="wireless"), AssetTag(tag="infrastructure")]
    asset.ports = [Port(port_number=80, protocol="tcp", service="http", state="open")]

    snapshot = build_inventory_snapshot([asset])
    entities = build_home_assistant_entities([asset])
    events = list_integration_events()

    assert snapshot["asset_count"] == 1
    exported_asset = snapshot["assets"][0]
    assert exported_asset["tags"] == ["infrastructure", "wireless"]
    assert exported_asset["ports"][0]["port_number"] == 80

    assert entities["entities"][0]["unique_id"] == "argus_assets_total"
    assert any(entity["unique_id"] == f"argus_asset_{asset.id}" for entity in entities["entities"])
    assert any(event["event"] == "new_device" for event in events)
