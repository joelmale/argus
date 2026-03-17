from __future__ import annotations

from typing import Protocol


class ArgusPlugin(Protocol):
    name: str
    version: str
    description: str

    async def on_asset_upserted(self, *, db_session, asset, result, change_type: str) -> None: ...
