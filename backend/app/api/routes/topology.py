"""Topology graph endpoints — nodes, edges, sub-graphs, and manual link editing."""
import hashlib
import json
from typing import Annotated
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.audit import log_audit_event
from app.db.models import Asset, TopologyLink, User
from app.db.session import get_db
from app.scanner.config import read_effective_scanner_config
from app.services.topology import load_topology_graph
from app.topology.graph_builder import (
    build_neighborhood_graph,
    build_segment_graph,
    build_topology_summary,
)

router = APIRouter()
DBSession = Annotated[AsyncSession, Depends(get_db)]
AdminUser = Annotated[User, Depends(get_current_admin)]
CurrentUser = Annotated[User, Depends(get_current_user)]


class TopologyLinkCreateRequest(BaseModel):
    source_id: UUID
    target_id: UUID
    link_type: str = "ethernet"
    relationship_type: str = "neighbor_l2"
    vlan_id: int | None = None
    observed: bool = True
    confidence: float = 1.0
    local_interface: str | None = None
    remote_interface: str | None = None
    ssid: str | None = None


class TopologyLinkUpdateRequest(BaseModel):
    observed: bool | None = None
    suppressed: bool | None = None
    confidence: float | None = None
    relationship_type: str | None = None
    local_interface: str | None = None
    remote_interface: str | None = None
    ssid: str | None = None


class TopologyLinkCorrectionRequest(BaseModel):
    source_id: UUID
    target_id: UUID
    relationship_type: str
    action: Literal["confirm", "suppress"]
    link_type: str = "inferred"
    confidence: float | None = None
    evidence: dict | None = None


class TopologyRoleUpdateRequest(BaseModel):
    topology_role: Literal["gateway", "gateway_candidate", "switch", "access_point", "infrastructure", "endpoint"] | None = None


async def _publish_topology_updated() -> None:
    """Emit a topology:updated WebSocket event via Redis pub/sub."""
    try:
        from app.workers.tasks import _publish_event  # noqa: PLC0415
        await _publish_event({"event": "topology:updated", "data": {}})
    except Exception:  # noqa: BLE001
        pass  # Never let a missing Redis connection block a topology write


def _etag_for_graph(graph: dict) -> str:
    raw = json.dumps(graph, sort_keys=True, default=str)
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()  # noqa: S324


@router.get("/graph")
async def get_topology_graph(request: Request, response: Response, db: DBSession, _: CurrentUser):
    graph = await load_topology_graph(db)
    etag = _etag_for_graph(graph)
    if request.headers.get("If-None-Match") == etag:
        return Response(status_code=304)
    response.headers["ETag"] = etag
    return graph


@router.get("/graph/summary")
async def get_topology_summary(db: DBSession, _: CurrentUser):
    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.orm import selectinload  # noqa: PLC0415
    from app.db.models import Asset, NetworkSegment  # noqa: PLC0415
    _, effective = await read_effective_scanner_config(db)
    assets = list((await db.execute(select(Asset).options(selectinload(Asset.tags)))).scalars().all())
    segments = list((await db.execute(select(NetworkSegment))).scalars().all())
    links = list((await db.execute(select(TopologyLink))).scalars().all())
    return build_topology_summary(assets, segments, links, prefix_v4=effective.topology_default_segment_prefix_v4)


@router.get("/graph/segment/{segment_id}")
async def get_segment_graph(segment_id: int, db: DBSession, _: CurrentUser):
    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.orm import selectinload  # noqa: PLC0415
    from app.db.models import Asset, NetworkSegment, TopologyLink  # noqa: PLC0415
    from app.topology.segments import infer_ipv4_segment_cidr  # noqa: PLC0415
    _, effective = await read_effective_scanner_config(db)
    
    segment = await db.get(NetworkSegment, segment_id)
    if not segment:
        raise HTTPException(status_code=404, detail="Segment not found")
        
    all_assets = (await db.execute(select(Asset.id, Asset.ip_address))).all()
    matching_ids = [
        row.id for row in all_assets
        if infer_ipv4_segment_cidr(row.ip_address, effective.topology_default_segment_prefix_v4) == segment.cidr
    ]
    
    assets = []
    links = []
    if matching_ids:
        assets = list((await db.execute(
            select(Asset)
            .options(selectinload(Asset.ports), selectinload(Asset.tags))
            .where(Asset.id.in_(matching_ids))
        )).scalars().all())
        links = list((await db.execute(
            select(TopologyLink).where(
                TopologyLink.source_id.in_(matching_ids),
                TopologyLink.target_id.in_(matching_ids)
            )
        )).scalars().all())
        
    segments = [segment]
    return build_segment_graph(segment_id, assets, segments, links, prefix_v4=effective.topology_default_segment_prefix_v4)


@router.get("/graph/neighborhood/{asset_id}")
async def get_neighborhood_graph(asset_id: UUID, db: DBSession, _: CurrentUser):
    from sqlalchemy import select, or_  # noqa: PLC0415
    from sqlalchemy.orm import selectinload  # noqa: PLC0415
    from app.db.models import Asset, NetworkSegment, TopologyLink  # noqa: PLC0415
    _, effective = await read_effective_scanner_config(db)
    
    links = list((await db.execute(
        select(TopologyLink).where(
            or_(TopologyLink.source_id == asset_id, TopologyLink.target_id == asset_id)
        )
    )).scalars().all())
    
    neighbor_ids = {asset_id}
    for link in links:
        neighbor_ids.add(link.source_id)
        neighbor_ids.add(link.target_id)
        
    assets = list((await db.execute(
        select(Asset)
        .options(selectinload(Asset.ports), selectinload(Asset.tags))
        .where(Asset.id.in_(neighbor_ids))
    )).scalars().all())
    
    segments = list((await db.execute(select(NetworkSegment))).scalars().all())
    return build_neighborhood_graph(str(asset_id), assets, segments, links, prefix_v4=effective.topology_default_segment_prefix_v4)


@router.post("/links", status_code=201)
async def create_topology_link(
    payload: TopologyLinkCreateRequest,
    db: DBSession,
    user: AdminUser,
):
    link = TopologyLink(
        source_id=payload.source_id,
        target_id=payload.target_id,
        link_type=payload.link_type,
        relationship_type=payload.relationship_type,
        vlan_id=payload.vlan_id,
        observed=payload.observed,
        confidence=payload.confidence,
        source="manual",
        local_interface=payload.local_interface,
        remote_interface=payload.remote_interface,
        ssid=payload.ssid,
        evidence={"operator_action": "manual_link_created"},
    )
    db.add(link)
    await db.flush()
    await log_audit_event(
        db,
        action="topology.link.created",
        user=user,
        target_type="topology_link",
        target_id=str(link.id),
        details={
            "source_id": str(payload.source_id),
            "target_id": str(payload.target_id),
            "relationship_type": payload.relationship_type,
        },
    )
    await db.commit()
    await db.refresh(link)
    await _publish_topology_updated()
    return link


@router.patch("/links/{link_id}")
async def update_topology_link(
    link_id: int,
    payload: TopologyLinkUpdateRequest,
    db: DBSession,
    user: AdminUser,
):
    link = await db.get(TopologyLink, link_id)
    if link is None:
        raise HTTPException(status_code=404, detail="Link not found")
    if payload.observed is not None:
        link.observed = payload.observed
        if payload.observed:
            link.source = "manual"
    if payload.suppressed is not None:
        link.suppressed = payload.suppressed
        if payload.suppressed:
            link.source = "manual_suppression"
        elif link.source == "manual_suppression":
            link.source = "manual"
    if payload.confidence is not None:
        link.confidence = payload.confidence
    if payload.relationship_type is not None:
        link.relationship_type = payload.relationship_type
    if payload.local_interface is not None:
        link.local_interface = payload.local_interface
    if payload.remote_interface is not None:
        link.remote_interface = payload.remote_interface
    if payload.ssid is not None:
        link.ssid = payload.ssid
    await log_audit_event(
        db,
        action="topology.link.updated",
        user=user,
        target_type="topology_link",
        target_id=str(link.id),
        details=payload.model_dump(exclude_unset=True, mode="json"),
    )
    await db.commit()
    await db.refresh(link)
    await _publish_topology_updated()
    return link


@router.post("/links/correction", status_code=201)
async def correct_topology_link(
    payload: TopologyLinkCorrectionRequest,
    db: DBSession,
    user: AdminUser,
):
    result = await db.execute(
        select(TopologyLink).where(
            TopologyLink.source_id == payload.source_id,
            TopologyLink.target_id == payload.target_id,
            TopologyLink.relationship_type == payload.relationship_type,
        )
    )
    link = result.scalar_one_or_none()
    if link is None:
        link = TopologyLink(
            source_id=payload.source_id,
            target_id=payload.target_id,
            link_type=payload.link_type,
            relationship_type=payload.relationship_type,
        )
        db.add(link)

    evidence = dict(link.evidence or {})
    evidence.update(payload.evidence or {})
    evidence["operator_action"] = f"inferred_link_{payload.action}ed"

    if payload.action == "confirm":
        link.observed = True
        link.suppressed = False
        link.confidence = payload.confidence if payload.confidence is not None else max(float(link.confidence or 0), 0.9)
        link.source = "manual"
    else:
        link.observed = False
        link.suppressed = True
        link.confidence = payload.confidence if payload.confidence is not None else 0.0
        link.source = "manual_suppression"
    link.evidence = evidence

    await db.flush()
    await log_audit_event(
        db,
        action=f"topology.link.{payload.action}ed",
        user=user,
        target_type="topology_link",
        target_id=str(link.id),
        details={
            "source_id": str(payload.source_id),
            "target_id": str(payload.target_id),
            "relationship_type": payload.relationship_type,
        },
    )
    await db.commit()
    await db.refresh(link)
    await _publish_topology_updated()
    return link


@router.patch("/nodes/{asset_id}/role")
async def update_topology_role(
    asset_id: UUID,
    payload: TopologyRoleUpdateRequest,
    db: DBSession,
    user: AdminUser,
):
    asset = await db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    custom_fields = dict(asset.custom_fields or {})
    if payload.topology_role is None:
        custom_fields.pop("topology_role_override", None)
    else:
        custom_fields["topology_role_override"] = payload.topology_role
    asset.custom_fields = custom_fields or None
    await log_audit_event(
        db,
        action="topology.node.role_updated",
        user=user,
        target_type="asset",
        target_id=str(asset.id),
        details={"topology_role": payload.topology_role},
    )
    await db.commit()
    await db.refresh(asset)
    await _publish_topology_updated()
    return {"asset_id": str(asset.id), "topology_role": payload.topology_role}


@router.delete("/links/{link_id}", status_code=204)
async def delete_topology_link(
    link_id: int,
    db: DBSession,
    user: AdminUser,
):
    link = await db.get(TopologyLink, link_id)
    if link is None:
        return
    await log_audit_event(
        db,
        action="topology.link.deleted",
        user=user,
        target_type="topology_link",
        target_id=str(link.id),
        details={"source_id": str(link.source_id), "target_id": str(link.target_id), "relationship_type": link.relationship_type},
    )
    await db.delete(link)
    await db.commit()
    await _publish_topology_updated()
