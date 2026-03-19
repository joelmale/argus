from __future__ import annotations

from app.fingerprinting.llm import build_fingerprint_prompt, parse_fingerprint_response


def test_build_fingerprint_prompt_includes_operator_guidance():
    prompt = build_fingerprint_prompt(
        asset={"ip_address": "192.168.100.4", "hostname": "proxmox2", "vendor": "Intel", "device_type": "unknown"},
        evidence=[
            {"source": "probe_http", "category": "identity", "key": "http_title", "value": "Proxmox Virtual Environment", "confidence": 0.9}
        ],
        prompt_suffix="Prefer homelab infrastructure classifications.",
    )

    assert "Proxmox Virtual Environment" in prompt
    assert "Prefer homelab infrastructure classifications." in prompt


def test_parse_fingerprint_response_handles_json_fence():
    parsed = parse_fingerprint_response(
        """```json
{"device_type":"server","vendor":"Proxmox","model":"VE","os_guess":"Debian","confidence":0.83,"summary":"Likely a Proxmox host.","supporting_evidence":["http_title=Proxmox Virtual Environment"]}
```"""
    )

    assert parsed["device_type"] == "server"
    assert parsed["confidence"] == 0.83
    assert parsed["supporting_evidence"] == ["http_title=Proxmox Virtual Environment"]
