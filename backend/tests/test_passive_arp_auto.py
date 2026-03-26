from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.scanner import config as scanner_config
from app.workers import tasks as worker_tasks


class _AsyncContext:
    def __init__(self, value):
        self._value = value

    async def __aenter__(self):
        return self._value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Engine:
    def __init__(self):
        self.disposed = False

    async def dispose(self):
        self.disposed = True


def test_detect_passive_arp_interface_prefers_route_to_targets(monkeypatch):
    monkeypatch.setattr(
        scanner_config,
        "_iter_route_entries",
        lambda: [
            scanner_config._RouteEntry(
                iface="eth0",
                network=scanner_config.ipaddress.ip_network("0.0.0.0/0"),
                is_default=True,
            ),
            scanner_config._RouteEntry(
                iface="br0",
                network=scanner_config.ipaddress.ip_network("192.168.100.0/23"),
                is_default=False,
            ),
        ],
    )

    assert scanner_config.detect_passive_arp_interface("192.168.100.5") == "br0"
    assert scanner_config.detect_passive_arp_interface("10.0.0.5") == "eth0"


def test_resolve_passive_arp_interface_uses_auto_for_missing_legacy_default(monkeypatch):
    monkeypatch.setattr(scanner_config.settings, "SCANNER_PASSIVE_ARP_INTERFACE", "eth0")
    monkeypatch.setattr(scanner_config, "_interface_exists", lambda ifname: ifname == "br0")
    monkeypatch.setattr(scanner_config, "detect_passive_arp_interface", lambda targets: "br0")

    assert scanner_config.resolve_passive_arp_interface("eth0", "192.168.100.0/23") == ("br0", True)
    assert scanner_config.resolve_passive_arp_interface("br0", "192.168.100.0/23") == ("br0", False)
    assert scanner_config.resolve_passive_arp_interface("auto", "192.168.100.0/23") == ("br0", True)


@pytest.mark.asyncio
async def test_passive_arp_loop_exits_when_no_viable_interface(monkeypatch, caplog):
    import app.scanner.config as scanner_config_module
    import sqlalchemy.ext.asyncio as sqlalchemy_asyncio

    engine = _Engine()
    fake_db = SimpleNamespace()

    monkeypatch.setattr(sqlalchemy_asyncio, "create_async_engine", lambda *args, **kwargs: engine)
    monkeypatch.setattr(sqlalchemy_asyncio, "async_sessionmaker", lambda *args, **kwargs: (lambda: _AsyncContext(fake_db)))
    monkeypatch.setattr(
        scanner_config_module,
        "get_or_create_scanner_config",
        lambda db: _completed(SimpleNamespace(passive_arp_interface="auto")),
    )
    monkeypatch.setattr(
        scanner_config_module,
        "build_effective_scanner_config",
        lambda config: SimpleNamespace(
            passive_arp_enabled=True,
            passive_arp_interface="auto",
            passive_arp_effective_interface=None,
            passive_arp_interface_auto=True,
            effective_targets="192.168.100.0/23",
        ),
    )

    await worker_tasks._passive_arp_loop()

    assert "no viable interface detected" in caplog.text
    assert engine.disposed is True


async def _completed(value):
    return value
