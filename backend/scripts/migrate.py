from __future__ import annotations

import os
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect


APP_TABLES = {
    "users",
    "assets",
    "ports",
    "asset_tags",
    "asset_history",
    "topology_links",
    "scan_jobs",
    "config_backup_targets",
    "config_backup_snapshots",
    "wireless_associations",
}

ROOT_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI_PATH = ROOT_DIR / "alembic.ini"


def _sync_database_url() -> str:
    return os.environ["DATABASE_URL"].replace("+asyncpg", "+psycopg2")


def main() -> None:
    config = Config(str(ALEMBIC_INI_PATH))
    config.set_main_option("sqlalchemy.url", _sync_database_url())

    engine = create_engine(_sync_database_url())
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    has_version_table = "alembic_version" in tables
    has_app_tables = bool(APP_TABLES & tables)

    if has_app_tables and not has_version_table:
        command.stamp(config, "head")
        engine.dispose()
        return

    command.upgrade(config, "head")
    engine.dispose()


if __name__ == "__main__":
    main()
