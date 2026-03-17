class ExampleArgusPlugin:
    name = "example-plugin"
    version = "0.1.0"
    description = "Example plugin that demonstrates Argus post-upsert hooks."
    capabilities = ["post_upsert", "health"]

    def health(self) -> str:
        return "healthy"

    async def on_asset_upserted(self, *, db_session, asset, result, change_type: str) -> None:
        # Example hook: a real plugin could post to an external webhook or enrich metadata.
        return None
