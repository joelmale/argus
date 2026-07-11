from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import select

from app.db.models import Asset, TopologyLink
from app.db.session import engine


@pytest.mark.asyncio
async def test_inferred_topology_link_can_be_suppressed(api_client, admin_user):
    source_id = uuid4()
    target_id = uuid4()

    async with engine.begin() as conn:
        await conn.execute(
            Asset.__table__.insert(),
            [
                {"id": source_id, "ip_address": "192.168.60.1", "hostname": "gateway", "device_type": "router", "status": "online"},
                {"id": target_id, "ip_address": "192.168.60.20", "hostname": "desktop", "device_type": "workstation", "status": "online"},
            ],
        )

    response = await api_client.post(
        "/api/v1/topology/links/correction",
        headers={"Authorization": f"Bearer {admin_user['token']}"},
        json={
            "source_id": str(source_id),
            "target_id": str(target_id),
            "relationship_type": "gateway_for",
            "action": "suppress",
            "evidence": {"reason": "operator rejected inferred gateway"},
        },
    )

    assert response.status_code == 201
    async with engine.begin() as conn:
        link = (
            await conn.execute(
                select(
                    TopologyLink.__table__.c.suppressed,
                    TopologyLink.__table__.c.source,
                    TopologyLink.__table__.c.evidence,
                ).where(
                    TopologyLink.source_id == source_id,
                    TopologyLink.target_id == target_id,
                    TopologyLink.relationship_type == "gateway_for",
                )
            )
        ).mappings().one()

    assert link["suppressed"] is True
    assert link["source"] == "manual_suppression"
    assert link["evidence"]["operator_action"] == "inferred_link_suppressed"


@pytest.mark.asyncio
async def test_topology_role_override_is_stored_on_asset(api_client, admin_user):
    asset_id = uuid4()

    async with engine.begin() as conn:
        await conn.execute(
            Asset.__table__.insert().values(
                id=asset_id,
                ip_address="192.168.61.10",
                hostname="lab-switch",
                device_type="unknown",
                status="online",
            )
        )

    response = await api_client.patch(
        f"/api/v1/topology/nodes/{asset_id}/role",
        headers={"Authorization": f"Bearer {admin_user['token']}"},
        json={"topology_role": "switch"},
    )

    assert response.status_code == 200
    async with engine.begin() as conn:
        custom_fields = (
            await conn.execute(
                select(Asset.__table__.c.custom_fields).where(Asset.id == asset_id)
            )
        ).scalar_one()

    assert custom_fields["topology_role_override"] == "switch"
