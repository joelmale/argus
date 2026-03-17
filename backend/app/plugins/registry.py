from __future__ import annotations

from importlib.metadata import entry_points
from typing import Any


def iter_plugins() -> list[Any]:
    plugins: list[Any] = []
    for entry in entry_points(group="argus.plugins"):
        try:
            plugin = entry.load()
            plugins.append(plugin() if callable(plugin) else plugin)
        except Exception:
            continue
    return plugins


def list_plugins() -> list[dict[str, str]]:
    return [
        {
            "name": getattr(plugin, "name", plugin.__class__.__name__),
            "version": getattr(plugin, "version", "unknown"),
            "description": getattr(plugin, "description", ""),
        }
        for plugin in iter_plugins()
    ]


async def run_post_upsert_hooks(*, db_session, asset, result, change_type: str) -> None:
    for plugin in iter_plugins():
        hook = getattr(plugin, "on_asset_upserted", None)
        if hook is None:
            continue
        await hook(db_session=db_session, asset=asset, result=result, change_type=change_type)
