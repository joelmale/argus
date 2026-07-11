from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.db.models import Asset, Finding, ScanJob
from app.db.session import engine


@pytest.mark.asyncio
async def test_operator_brief_groups_daily_use_signals(api_client, viewer_user):
    now = datetime.now(timezone.utc)
    asset_id = uuid4()
    scan_id = uuid4()

    async with engine.begin() as conn:
        await conn.execute(
            Asset.__table__.insert().values(
                id=asset_id,
                ip_address="192.168.50.25",
                hostname=None,
                vendor=None,
                device_type=None,
                status="online",
                first_seen=now,
                last_seen=now,
            )
        )
        await conn.execute(
            Finding.__table__.insert().values(
                asset_id=asset_id,
                source_tool="import",
                title="Critical service exposure",
                description="A critical imported finding is open.",
                severity="critical",
                status="open",
                first_seen=now,
                last_seen=now,
            )
        )
        await conn.execute(
            ScanJob.__table__.insert().values(
                id=scan_id,
                targets="192.168.50.0/24",
                scan_type="balanced",
                status="failed",
                triggered_by="manual",
                created_at=now,
                started_at=now,
                finished_at=now,
            )
        )

    response = await api_client.get(
        "/api/v1/system/operator-brief",
        headers={"Authorization": f"Bearer {viewer_user['token']}"},
    )

    assert response.status_code == 200
    payload = response.json()
    sections = {section["key"]: section for section in payload["sections"]}

    assert payload["summary"]["changed"] >= 1
    assert payload["summary"]["attention"] >= 1
    assert payload["summary"]["unknowns"] >= 1
    assert payload["summary"]["risk"] >= 1
    assert sections["changed"]["question"] == "What changed?"
    assert sections["recommendations"]["items"]
    assert any(item["target_type"] == "asset" for item in sections["unknowns"]["items"])
    assert any(item["severity"] == "critical" for item in sections["risk"]["items"])
