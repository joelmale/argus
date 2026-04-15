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
from app.scanner.config import read_effective_scanner_config
from app.topology.graph_builder import build_topology_graph

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
    _, effective = await read_effective_scanner_config(db)
    assets_result = await db.execute(select(Asset).options(selectinload(Asset.ports), selectinload(Asset.tags)))
    assets = assets_result.scalars().all()
    segments_result = await db.execute(select(NetworkSegment))
    segments = segments_result.scalars().all()
    links_result = await db.execute(select(TopologyLink))
    links = links_result.scalars().all()
    return build_topology_graph(
        assets,
        segments,
        links,
        prefix_v4=effective.topology_default_segment_prefix_v4,
    )


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
