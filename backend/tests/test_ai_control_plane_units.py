from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.api.routes import system as system_routes
from app.scanner.models import DeviceClass, DiscoveredHost, OSFingerprint, PortResult
from app.scanner.stages.fingerprint import classify
from app.fingerprinting.evidence import _signature_evidence


def test_console_hostname_and_vendor_hints_classify_as_game_console():
    hint = classify(
        DiscoveredHost(ip_address="192.168.1.50", nmap_hostname="ps5-livingroom"),
        [PortResult(port=9308, state="open", protocol="tcp", service="tcpwrapped")],
        OSFingerprint(),
        "Sony Interactive Entertainment",
    )

    assert hint.device_class == DeviceClass.GAME_CONSOLE
    assert hint.confidence >= 0.86


def test_signature_evidence_emits_game_console_and_vendor_matches():
    matches = _signature_evidence("PlayStation 5 by Sony Interactive Entertainment", "probe_http", {})
    values = {(item.category, item.value) for item in matches}

    assert ("device_type", "game_console") in values
    assert ("vendor", "Sony") in values


@pytest.mark.asyncio
async def test_ollama_model_routes_use_saved_base_url(monkeypatch):
    effective = SimpleNamespace(ollama_base_url="http://ollama.local:11434/v1")

    async def fake_read_effective(_db):
        return None, effective

    monkeypatch.setattr(system_routes, "read_effective_scanner_config", fake_read_effective)
    async def fake_list_models(base_url: str):
        return {"base_url": base_url, "api_root": "http://ollama.local:11434", "models": [{"name": "qwen2.5:7b"}]}

    monkeypatch.setattr(system_routes, "_list_ollama_models", fake_list_models)
    listed = await system_routes.get_ollama_models(object(), object(), None)
    assert listed["base_url"] == "http://ollama.local:11434/v1"

    recorded = {}

    async def fake_pull(base_url: str, model: str):
        recorded["base_url"] = base_url
        recorded["model"] = model
        return {"base_url": base_url, "api_root": "http://ollama.local:11434", "model": model, "status": "success"}

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(system_routes, "_pull_ollama_model", fake_pull)
    monkeypatch.setattr(system_routes, "log_audit_event", fake_audit)
    db = SimpleNamespace(commit=lambda: None)

    async def _commit():
        return None

    db.commit = _commit
    result = await system_routes.pull_ollama_model(
        system_routes.OllamaPullRequest(model="qwen2.5:7b"),
        SimpleNamespace(id="admin"),
        db,
    )
    assert recorded == {"base_url": "http://ollama.local:11434/v1", "model": "qwen2.5:7b"}
    assert result["status"] == "success"
