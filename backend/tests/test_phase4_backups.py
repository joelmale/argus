import pytest

from app.backups import BACKUP_DRIVERS, list_backup_drivers


def test_backup_drivers_include_phase4_platforms():
    names = {driver["name"] for driver in list_backup_drivers()}

    assert {"cisco_ios", "juniper_junos", "mikrotik_routeros", "openwrt"} <= names
    assert BACKUP_DRIVERS["cisco_ios"].commands[-1] == "show running-config"


def test_plugin_registry_is_safe_without_entry_points():
    from app.plugins.registry import list_plugins

    plugins = list_plugins()

    assert isinstance(plugins, list)
