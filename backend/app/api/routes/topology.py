"""Topology graph endpoints — nodes, edges, sub-graphs, and manual link editing."""
import hashlib
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_admin, get_current_user
from app.db.models import TopologyLink, User
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
    from app.db.models import Asset, NetworkSegment  # noqa: PLC0415
    _, effective = await read_effective_scanner_config(db)
    assets = list((await db.execute(select(Asset).options(selectinload(Asset.ports), selectinload(Asset.tags)))).scalars().all())
    segments = list((await db.execute(select(NetworkSegment))).scalars().all())
    links = list((await db.execute(select(TopologyLink))).scalars().all())
    return build_segment_graph(segment_id, assets, segments, links, prefix_v4=effective.topology_default_segment_prefix_v4)


@router.get("/graph/neighborhood/{asset_id}")
async def get_neighborhood_graph(asset_id: UUID, db: DBSession, _: CurrentUser):
    from sqlalchemy import select  # noqa: PLC0415
    from sqlalchemy.orm import selectinload  # noqa: PLC0415
    from app.db.models import Asset, NetworkSegment  # noqa: PLC0415
    _, effective = await read_effective_scanner_config(db)
    assets = list((await db.execute(select(Asset).options(selectinload(Asset.ports), selectinload(Asset.tags)))).scalars().all())
    segments = list((await db.execute(select(NetworkSegment))).scalars().all())
    links = list((await db.execute(select(TopologyLink))).scalars().all())
    return build_neighborhood_graph(str(asset_id), assets, segments, links, prefix_v4=effective.topology_default_segment_prefix_v4)


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
        relationship_type=payload.relationship_type,
        vlan_id=payload.vlan_id,
        observed=payload.observed,
        confidence=payload.confidence,
        source="manual",
        local_interface=payload.local_interface,
        remote_interface=payload.remote_interface,
        ssid=payload.ssid,
    )
    db.add(link)
    await db.commit()
    await db.refresh(link)
    await _publish_topology_updated()
    return link


@router.patch("/links/{link_id}")
async def update_topology_link(
    link_id: int,
    payload: TopologyLinkUpdateRequest,
    db: DBSession,
    _: AdminUser,
):
    link = await db.get(TopologyLink, link_id)
    if link is None:
        raise HTTPException(status_code=404, detail="Link not found")
    if payload.observed is not None:
        link.observed = payload.observed
        if payload.observed and link.source == "inference":
            link.source = "manual"
    if payload.suppressed is not None:
        link.suppressed = payload.suppressed
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
    await db.commit()
    await db.refresh(link)
    await _publish_topology_updated()
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
    await _publish_topology_updated()
