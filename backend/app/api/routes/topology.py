"""Topology graph endpoints — returns nodes + edges for frontend rendering."""
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import get_current_admin, get_current_user
from app.db.models import Asset, NetworkSegment, TopologyLink, User
from app.db.session import get_db
from app.topology.segments import infer_ipv4_segment_cidr, infer_topology_role, pick_gateway_candidates

router = APIRouter()
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
CurrentUser = Annotated[User, Depends(get_current_user)]


class TopologyLinkCreateRequest(BaseModel):
    source_id: UUID
    target_id: UUID
    link_type: str = "ethernet"
    vlan_id: int | None = None


@router.get("/graph")
async def get_topology_graph(db: DBSession, _: CurrentUser):
    """
    Returns a Cytoscape.js-compatible graph payload:
      { nodes: [{data: {id, label, ...}}], edges: [{data: {source, target, ...}}] }
    """
    assets_result = await db.execute(select(Asset).options(selectinload(Asset.ports)))
    assets = assets_result.scalars().all()

    segments_result = await db.execute(select(NetworkSegment))
    segments = segments_result.scalars().all()

    links_result = await db.execute(select(TopologyLink))
    links = links_result.scalars().all()

    gateway_candidates = pick_gateway_candidates(assets)
    gateway_ids = {str(asset.id) for asset in gateway_candidates.values()}
    segment_id_by_cidr = {segment.cidr: segment.id for segment in segments}

    nodes = []
    for asset in assets:
        segment_cidr = infer_ipv4_segment_cidr(asset.ip_address)
        topology_role, topology_confidence = infer_topology_role(asset, gateway_ids)
        nodes.append(
            {
                "data": {
                    "id": str(asset.id),
                    "label": asset.hostname or asset.ip_address,
                    "ip": asset.ip_address,
                    "vendor": asset.vendor,
                    "os": asset.os_name,
                    "status": asset.status,
                    "device_type": asset.effective_device_type,
                    "segment_cidr": segment_cidr,
                    "segment_id": segment_id_by_cidr.get(segment_cidr or ""),
                    "topology_role": topology_role,
                    "topology_confidence": topology_confidence,
                    "is_gateway": str(asset.id) in gateway_ids,
                }
            }
        )

    edges = [
        {
            "data": {
                "id": f"e{link.id}",
                "source": str(link.source_id),
                "target": str(link.target_id),
                "link_type": link.link_type,
                "relationship_type": link.relationship_type,
                "observed": link.observed,
                "confidence": link.confidence,
                "source_kind": link.source,
                "segment_id": link.segment_id,
                "local_interface": link.local_interface,
                "remote_interface": link.remote_interface,
                "ssid": link.ssid,
                "vlan_id": link.vlan_id,
            }
        }
        for link in links
    ]

    serialized_segments = [
        {
            "id": segment.id,
            "cidr": segment.cidr,
            "label": segment.label,
            "vlan_id": segment.vlan_id,
            "gateway_asset_id": str(segment.gateway_asset_id) if segment.gateway_asset_id else str(gateway_candidates.get(segment.cidr).id) if gateway_candidates.get(segment.cidr) else None,
            "confidence": segment.confidence,
            "source": segment.source,
        }
        for segment in segments
    ]

    return {"nodes": nodes, "edges": edges, "segments": serialized_segments}


@router.post("/links", status_code=201)
async def create_topology_link(
    payload: TopologyLinkCreateRequest,
    db: DBSession,
    _: AdminUser,
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
    db: DBSession,
    _: AdminUser,
):
    link = await db.get(TopologyLink, link_id)
    if link is None:
        return
    await db.delete(link)
    await db.commit()
