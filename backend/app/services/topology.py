from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.models import Asset, NetworkSegment, TopologyLink
from app.scanner.config import read_effective_scanner_config
from app.topology.graph_builder import build_topology_graph


async def load_topology_graph(db: AsyncSession) -> dict:
    _, effective = await read_effective_scanner_config(db)
    assets_result = await db.execute(select(Asset).options(selectinload(Asset.ports), selectinload(Asset.tags)))
    segments_result = await db.execute(select(NetworkSegment))
    links_result = await db.execute(select(TopologyLink))
    return build_topology_graph(
        list(assets_result.scalars().all()),
        list(segments_result.scalars().all()),
        list(links_result.scalars().all()),
        prefix_v4=effective.topology_default_segment_prefix_v4,
    )

