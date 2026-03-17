"""Topology graph endpoints — returns nodes + edges for frontend rendering."""
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.db.models import Asset, TopologyLink, User
from app.db.session import get_db

router = APIRouter()


class TopologyLinkCreateRequest(BaseModel):
    source_id: UUID
    target_id: UUID
    link_type: str = "ethernet"
    vlan_id: int | None = None


@router.get("/graph")
async def get_topology_graph(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    """
    Returns a Cytoscape.js-compatible graph payload:
      { nodes: [{data: {id, label, ...}}], edges: [{data: {source, target, ...}}] }
    """
    assets_result = await db.execute(select(Asset))
    assets = assets_result.scalars().all()

    links_result = await db.execute(select(TopologyLink))
    links = links_result.scalars().all()

    nodes = [
        {
            "data": {
                "id": str(a.id),
                "label": a.hostname or a.ip_address,
                "ip": a.ip_address,
                "vendor": a.vendor,
                "os": a.os_name,
                "status": a.status,
                "device_type": a.device_type,
            }
        }
        for a in assets
    ]

    edges = [
        {
            "data": {
                "id": f"e{link.id}",
                "source": str(link.source_id),
                "target": str(link.target_id),
                "link_type": link.link_type,
                "vlan_id": link.vlan_id,
            }
        }
        for link in links
    ]

    return {"nodes": nodes, "edges": edges}


@router.post("/links", status_code=201)
async def create_topology_link(
    payload: TopologyLinkCreateRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    link = TopologyLink(
        source_id=payload.source_id,
        target_id=payload.target_id,
        link_type=payload.link_type,
        vlan_id=payload.vlan_id,
    )
    db.add(link)
    await db.commit()
    await db.refresh(link)
    return link


@router.delete("/links/{link_id}", status_code=204)
async def delete_topology_link(
    link_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_admin),
):
    link = await db.get(TopologyLink, link_id)
    if link is None:
        return
    await db.delete(link)
    await db.commit()
