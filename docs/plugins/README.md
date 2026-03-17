# Argus Plugin Development

Argus plugins are standard Python packages exposed through the `argus.plugins` entry-point group.

## What a plugin can do today

- receive `on_asset_upserted` hooks after discovery and enrichment
- declare capabilities for the admin UI
- report a simple health status string

Phase 5 keeps the plugin API intentionally small. The goal is to make custom homelab integrations easy to ship without introducing a heavy plugin runtime.

## Minimal plugin structure

```text
example_argus_plugin/
  pyproject.toml
  example_argus_plugin/
    __init__.py
```

## Required entry point

Register a plugin class in `pyproject.toml`:

```toml
[project.entry-points."argus.plugins"]
example = "example_argus_plugin:ExampleArgusPlugin"
```

## Recommended plugin contract

```python
class ExampleArgusPlugin:
    name = "example-plugin"
    version = "0.1.0"
    description = "Example Argus plugin"
    capabilities = ["post_upsert", "webhook"]

    def health(self) -> str:
        return "healthy"

    async def on_asset_upserted(self, *, db_session, asset, result, change_type: str) -> None:
        ...
```

## Installing a plugin in dev

From the plugin package directory:

```bash
pip install -e .
```

Then restart the backend container:

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml restart backend
```

The plugin should appear in the Settings page under `Backup Drivers & Plugins`.

## Notes

- Keep plugins idempotent. Discovery hooks may run many times.
- Do not block the scan pipeline with long synchronous work.
- Treat Argus models as internal APIs that may evolve between roadmap phases.
- Prefer external side effects like webhook posting, ticket creation, or metadata enrichment over direct schema changes from plugins.
