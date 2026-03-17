from datetime import datetime, timezone
from uuid import uuid4

import pytest

from app.db.models import Asset, Port
from app.db.session import AsyncSessionLocal
from app.findings import ingest_findings, summarize_findings


@pytest.mark.asyncio
async def test_ingest_findings_creates_and_updates_records():
    asset_id = uuid4()
    ip_address = f"192.168.200.{asset_id.int % 200 + 20}"
    async with AsyncSessionLocal() as db:
        asset = Asset(
            id=asset_id,
            ip_address=ip_address,
            hostname=f"core-sw-{asset_id.hex[:6]}",
            status="online",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        db.add(asset)
        await db.flush()
        db.add(Port(asset_id=asset.id, port_number=443, protocol="tcp", service="https", state="open"))
        await db.commit()

        first = await ingest_findings(
            db,
            [
                {
                    "ip_address": ip_address,
                    "title": "Weak TLS Cipher",
                    "severity": "medium",
                    "port_number": 443,
                    "protocol": "tcp",
                }
            ],
            source_default="nmap_nse",
        )
        second = await ingest_findings(
            db,
            [
                {
                    "ip_address": ip_address,
                    "title": "Weak TLS Cipher",
                    "severity": "high",
                    "port_number": 443,
                    "protocol": "tcp",
                }
            ],
            source_default="nmap_nse",
        )
        summary = await summarize_findings(db)
        await db.delete(asset)
        await db.commit()

    assert first == {"created": 1, "updated": 0, "skipped": 0}
    assert second == {"created": 0, "updated": 1, "skipped": 0}
    assert summary["total"] == 1
    assert summary["severity_counts"]["high"] == 1
