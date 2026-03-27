from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.db.models import Asset
from app.workers.tasks import (
    _apply_asset_heartbeat,
    _heartbeat_slot_count,
    _heartbeat_slot_for_asset,
    _select_assets_for_heartbeat_slot,
    _reconcile_asset_heartbeats,
)


def _asset(
    ip_address: str,
    *,
    status: str = "online",
    heartbeat_missed_count: int = 0,
    last_seen: datetime | None = None,
) -> Asset:
    now = datetime.now(timezone.utc)
    return Asset(
        id=uuid4(),
        ip_address=ip_address,
        status=status,
        heartbeat_missed_count=heartbeat_missed_count,
        first_seen=now,
        last_seen=last_seen or now,
    )


def test_apply_asset_heartbeat_marks_offline_only_after_third_consecutive_miss():
    asset = _asset("192.168.1.10")
    checked_at = datetime.now(timezone.utc)

    assert _apply_asset_heartbeat(asset, is_reachable=False, checked_at=checked_at, miss_threshold=3) is None
    assert asset.status == "online"
    assert asset.heartbeat_missed_count == 1

    assert _apply_asset_heartbeat(
        asset,
        is_reachable=False,
        checked_at=checked_at + timedelta(seconds=30),
        miss_threshold=3,
    ) is None
    assert asset.status == "online"
    assert asset.heartbeat_missed_count == 2

    diff = _apply_asset_heartbeat(
        asset,
        is_reachable=False,
        checked_at=checked_at + timedelta(seconds=60),
        miss_threshold=3,
    )
    assert diff == {"old": "online", "new": "offline"}
    assert asset.status == "offline"
    assert asset.heartbeat_missed_count == 3


def test_apply_asset_heartbeat_recovers_offline_asset_on_successful_check():
    previous_seen = datetime.now(timezone.utc) - timedelta(minutes=10)
    asset = _asset(
        "192.168.1.20",
        status="offline",
        heartbeat_missed_count=3,
        last_seen=previous_seen,
    )
    checked_at = datetime.now(timezone.utc)

    diff = _apply_asset_heartbeat(asset, is_reachable=True, checked_at=checked_at, miss_threshold=3)

    assert diff == {"old": "offline", "new": "online"}
    assert asset.status == "online"
    assert asset.heartbeat_missed_count == 0
    assert asset.last_seen == checked_at
    assert asset.heartbeat_last_checked_at == checked_at


def test_reconcile_asset_heartbeats_collects_newly_offline_notifications_only():
    checked_at = datetime.now(timezone.utc)
    online_asset = _asset(
        "192.168.1.30",
        status="online",
        heartbeat_missed_count=2,
        last_seen=checked_at - timedelta(minutes=3),
    )
    offline_asset = _asset(
        "192.168.1.31",
        status="offline",
        heartbeat_missed_count=3,
        last_seen=checked_at - timedelta(minutes=5),
    )

    status_changes, offline_notifications = _reconcile_asset_heartbeats(
        [online_asset, offline_asset],
        responsive_ips=set(),
        checked_at=checked_at,
        miss_threshold=3,
    )

    assert [(asset.ip_address, diff) for asset, diff in status_changes] == [
        ("192.168.1.30", {"old": "online", "new": "offline"}),
    ]
    assert offline_notifications == [
        {
            "ip": "192.168.1.30",
            "hostname": None,
            "last_seen": (checked_at - timedelta(minutes=3)).isoformat(),
        }
    ]


def test_select_assets_for_heartbeat_slot_staggers_assets_across_full_cycle():
    checked_at = datetime(2026, 3, 26, 12, 0, 0, tzinfo=timezone.utc)
    assets = [_asset(f"192.168.1.{index}") for index in range(10, 22)]
    slot_count = _heartbeat_slot_count(interval_seconds=10, target_interval_seconds=30)

    selected_ids = set()
    slot_sizes = []
    for offset in (0, 10, 20):
        slot_assets = _select_assets_for_heartbeat_slot(
            assets,
            checked_at=checked_at + timedelta(seconds=offset),
            interval_seconds=10,
            slot_count=slot_count,
        )
        slot_sizes.append(len(slot_assets))
        selected_ids.update(asset.ip_address for asset in slot_assets)

    assert slot_count == 3
    assert selected_ids == {asset.ip_address for asset in assets}
    assert all(size > 0 for size in slot_sizes)


def test_heartbeat_slot_for_asset_is_stable():
    asset = _asset("192.168.1.50")
    slot_count = 3

    assert _heartbeat_slot_for_asset(asset, slot_count=slot_count) == _heartbeat_slot_for_asset(asset, slot_count=slot_count)
