"""Assets CRUD — the core inventory endpoints."""
import csv
from io import StringIO
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_admin, get_current_user
from app.db.models import Asset, AssetHistory, AssetTag, Port, User
from app.db.session import get_db

router = APIRouter()


class AssetTagRequest(BaseModel):
    tag: str


@router.get("/")
async def list_assets(
    search: str | None = Query(None, description="Search by IP, hostname, or vendor"),
    status: str | None = Query(None, description="Filter by status: online | offline"),
    tag: str | None = Query(None, description="Filter by tag"),
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return all discovered assets with optional filtering."""
    q = select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports))
    if status:
        q = q.where(Asset.status == status)
    if search:
        like = f"%{search}%"
        q = q.where(
            Asset.ip_address.ilike(like)
            | Asset.hostname.ilike(like)
            | Asset.vendor.ilike(like)
        )
    if tag:
        q = q.join(AssetTag).where(AssetTag.tag == tag)
    q = q.offset(skip).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/export.csv")
async def export_assets_csv(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports)))
    assets = result.scalars().all()

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "id",
        "ip_address",
        "hostname",
        "mac_address",
        "vendor",
        "os_name",
        "device_type",
        "status",
        "first_seen",
        "last_seen",
        "tags",
        "custom_fields",
    ])
    for asset in assets:
        writer.writerow(
            [
                str(asset.id),
                asset.ip_address,
                asset.hostname or "",
                asset.mac_address or "",
                asset.vendor or "",
                asset.os_name or "",
                asset.device_type or "",
                asset.status,
                asset.first_seen.isoformat(),
                asset.last_seen.isoformat(),
                ",".join(sorted(tag.tag for tag in asset.tags)),
                asset.custom_fields or {},
            ]
        )

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="argus-assets.csv"'},
    )


@router.get("/report.html", response_class=HTMLResponse)
async def export_assets_report_html(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Asset).options(selectinload(Asset.tags), selectinload(Asset.ports)))
    assets = result.scalars().all()

    total = len(assets)
    online = sum(1 for asset in assets if asset.status == "online")
    offline = sum(1 for asset in assets if asset.status == "offline")

    rows = "".join(
        f"<tr><td>{asset.ip_address}</td><td>{asset.hostname or ''}</td><td>{asset.vendor or ''}</td><td>{asset.device_type or ''}</td><td>{asset.status}</td><td>{', '.join(tag.tag for tag in asset.tags)}</td></tr>"
        for asset in assets
    )
    return HTMLResponse(
        f"""
        <html>
          <head>
            <title>Argus Inventory Report</title>
            <style>
              body {{ font-family: sans-serif; margin: 32px; color: #18181b; }}
              h1 {{ margin-bottom: 8px; }}
              .summary {{ display: flex; gap: 16px; margin: 16px 0 24px; }}
              .card {{ border: 1px solid #d4d4d8; border-radius: 12px; padding: 12px 16px; }}
              table {{ width: 100%; border-collapse: collapse; }}
              th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid #e4e4e7; font-size: 14px; }}
              th {{ background: #f4f4f5; }}
            </style>
          </head>
          <body>
            <h1>Argus Inventory Report</h1>
            <p>Generated from the current inventory snapshot.</p>
            <div class="summary">
              <div class="card"><strong>Total assets:</strong> {total}</div>
              <div class="card"><strong>Online:</strong> {online}</div>
              <div class="card"><strong>Offline:</strong> {offline}</div>
            </div>
            <table>
              <thead>
                <tr><th>IP</th><th>Hostname</th><th>Vendor</th><th>Type</th><th>Status</th><th>Tags</th></tr>
              </thead>
              <tbody>{rows}</tbody>
            </table>
          </body>
        </html>
        """
    )


@router.get("/{asset_id}")
async def get_asset(asset_id: UUID, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    stmt = (
        select(Asset)
        .options(
            selectinload(Asset.ports),
            selectinload(Asset.tags),
            selectinload(Asset.history),
        )
        .where(Asset.id == asset_id)
    )
    asset = (await db.execute(stmt)).scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.patch("/{asset_id}")
async def update_asset(
    asset_id: UUID,
    payload: dict,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    """Update mutable fields: hostname, notes, tags, custom_fields."""
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    allowed = {"hostname", "notes", "custom_fields", "device_type"}
    for key, val in payload.items():
        if key in allowed:
            setattr(asset, key, val)
    await db.commit()
    await db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=204)
async def delete_asset(asset_id: UUID, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_admin)):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    await db.delete(asset)
    await db.commit()


@router.get("/{asset_id}/history")
async def get_asset_history(asset_id: UUID, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    result = await db.execute(
        select(AssetHistory)
        .where(AssetHistory.asset_id == asset_id)
        .order_by(AssetHistory.changed_at.desc())
    )
    return result.scalars().all()


@router.get("/{asset_id}/ports")
async def get_asset_ports(asset_id: UUID, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    result = await db.execute(
        select(Port)
        .where(Port.asset_id == asset_id)
        .order_by(Port.port_number.asc(), Port.protocol.asc())
    )
    return result.scalars().all()


@router.post("/{asset_id}/tags", status_code=201)
async def add_asset_tag(
    asset_id: UUID,
    payload: AssetTagRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    normalized = payload.tag.strip().lower()
    if not normalized:
        raise HTTPException(status_code=400, detail="Tag cannot be empty")

    existing = await db.execute(
        select(AssetTag).where(AssetTag.asset_id == asset_id, AssetTag.tag == normalized)
    )
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Tag already exists")

    tag = AssetTag(asset_id=asset_id, tag=normalized)
    db.add(tag)
    await db.commit()
    await db.refresh(tag)
    return tag


@router.delete("/{asset_id}/tags/{tag}", status_code=204)
async def delete_asset_tag(
    asset_id: UUID,
    tag: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    result = await db.execute(
        select(AssetTag).where(AssetTag.asset_id == asset_id, AssetTag.tag == tag.lower())
    )
    asset_tag = result.scalar_one_or_none()
    if asset_tag is None:
        return
    await db.delete(asset_tag)
    await db.commit()
