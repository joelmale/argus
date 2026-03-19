from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, AssetEvidence, PassiveObservation


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def record_passive_observation(
    db: AsyncSession,
    *,
    asset: Asset,
    source: str,
    event_type: str,
    summary: str,
    details: dict | None = None,
    observed_at: datetime | None = None,
) -> PassiveObservation:
    ts = observed_at or _utcnow()
    observation = PassiveObservation(
        asset_id=asset.id,
        source=source,
        event_type=event_type,
        summary=summary[:512],
        details=details or {},
        observed_at=ts,
    )
    db.add(observation)

    for row in _build_passive_evidence(asset=asset, source=source, event_type=event_type, details=details or {}, observed_at=ts):
        db.add(row)

    await db.flush()
    return observation


def _build_passive_evidence(
    *,
    asset: Asset,
    source: str,
    event_type: str,
    details: dict,
    observed_at: datetime,
) -> list[AssetEvidence]:
    rows: list[AssetEvidence] = [
        AssetEvidence(
            asset_id=asset.id,
            source=source,
            category="presence",
            key=f"passive_{event_type}",
            value=details.get("ip") or asset.ip_address,
            confidence=0.68,
            details=details,
            observed_at=observed_at,
        )
    ]

    hostname = details.get("hostname")
    if hostname:
        rows.append(
            AssetEvidence(
                asset_id=asset.id,
                source=source,
                category="identity",
                key="observed_hostname",
                value=str(hostname),
                confidence=0.76,
                details=details,
                observed_at=observed_at,
            )
        )

    mac_address = details.get("mac") or asset.mac_address
    if mac_address:
        rows.append(
            AssetEvidence(
                asset_id=asset.id,
                source=source,
                category="identity",
                key="observed_mac",
                value=str(mac_address),
                confidence=0.74,
                details=details,
                observed_at=observed_at,
            )
        )

    service_name = details.get("service_name")
    if service_name:
        rows.append(
            AssetEvidence(
                asset_id=asset.id,
                source=source,
                category="identity",
                key="passive_service",
                value=str(service_name),
                confidence=0.72,
                details=details,
                observed_at=observed_at,
            )
        )
    return rows
