"""Topology graph endpoints — returns nodes + edges for frontend rendering."""
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, TopologyLink
from app.db.session import get_db

router = APIRouter()


@router.get("/graph")
async def get_topology_graph(db: AsyncSession = Depends(get_db)):
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
