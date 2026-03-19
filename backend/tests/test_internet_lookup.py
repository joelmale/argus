from __future__ import annotations

from app.fingerprinting.internet_lookup import build_lookup_query, domain_is_allowed, normalize_allowed_domains, parse_search_results


def test_normalize_allowed_domains_and_domain_matching():
    allowed = normalize_allowed_domains("docs.tp-link.com, proxmox.com ,ui.com")

    assert allowed == ["docs.tp-link.com", "proxmox.com", "ui.com"]
    assert domain_is_allowed("https://docs.tp-link.com/en/", allowed) is True
    assert domain_is_allowed("https://pve.proxmox.com/wiki/Main_Page", allowed) is True
    assert domain_is_allowed("https://example.com", allowed) is False


def test_build_lookup_query_prefers_asset_and_evidence_terms():
    query = build_lookup_query(
        {"hostname": "proxmox2", "vendor": "Intel", "device_type": "unknown"},
        [{"category": "identity", "value": "Proxmox Virtual Environment"}],
    )

    assert query is not None
    assert "proxmox2" in query
    assert "Intel" in query


def test_parse_search_results_filters_domains():
    html = """
    <a class="result__a" href="https://docs.tp-link.com/us/deco-xe75/">Deco XE75</a>
    <div class="result__snippet">TP-Link setup guide.</div>
    <a class="result__a" href="https://example.com/random">Random</a>
    <div class="result__snippet">Ignore me.</div>
    """
    results = parse_search_results(html, ["docs.tp-link.com"])

    assert len(results) == 1
    assert results[0]["domain"] == "docs.tp-link.com"
    assert results[0]["title"] == "Deco XE75"
