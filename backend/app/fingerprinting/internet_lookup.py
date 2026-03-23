from __future__ import annotations

import re
from urllib.parse import quote_plus, urlparse

import httpx


SEARCH_ENDPOINT = "https://duckduckgo.com/html/?q={query}"
RESULT_LINK_RE = re.compile(
    r'<a[^>]+class="[^"]*result__a[^"]*"[^>]+href="(?P<url>[^"]+)"[^>]*>(?P<title>.*?)</a>',
    re.IGNORECASE | re.DOTALL,
)
RESULT_SNIPPET_RE = re.compile(
    r'(?:<a[^>]+class="[^"]*result__snippet[^"]*"[^>]*>|<div[^>]+class="[^"]*result__snippet[^"]*"[^>]*>)(?P<snippet>.*?)</(?:a|div)>',
    re.IGNORECASE | re.DOTALL,
)
TAG_RE = re.compile(r"<[^>]+>")


def normalize_allowed_domains(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip().lower() for item in value.split(",") if item.strip()]


def build_lookup_query(asset: dict, evidence: list[dict]) -> str | None:
    terms: list[str] = []
    for key in ("hostname", "vendor", "device_type"):
        value = asset.get(key)
        if value and value != "unknown":
            terms.append(str(value))
    for item in evidence[:8]:
        if item.get("category") in {"vendor", "model", "identity", "service"}:
            value = str(item.get("value", "")).strip()
            if value and value not in terms:
                terms.append(value)
        if len(terms) >= 4:
            break
    if len(terms) < 2:
        return None
    return " ".join(terms[:4])


def domain_is_allowed(url: str, allowed_domains: list[str]) -> bool:
    if not allowed_domains:
        return False
    hostname = (urlparse(url).hostname or "").lower()
    return any(hostname == domain or hostname.endswith(f".{domain}") for domain in allowed_domains)


def parse_search_results(html: str, allowed_domains: list[str]) -> list[dict]:
    results: list[dict] = []
    for match in RESULT_LINK_RE.finditer(html):
        url = httpx.URL(match.group("url")).copy_with(fragment=None)
        if not domain_is_allowed(str(url), allowed_domains):
            continue
        snippet = _extract_result_snippet(html, match.end())
        title = TAG_RE.sub("", match.group("title")).strip()
        results.append(
            {
                "url": str(url),
                "domain": url.host or "",
                "title": title[:512],
                "snippet": snippet[:1000],
            }
        )
    return results


def _extract_result_snippet(html: str, anchor_end: int) -> str:
    window = html[anchor_end: anchor_end + 3000]
    snippet_match = RESULT_SNIPPET_RE.search(window)
    if not snippet_match:
        return ""
    return TAG_RE.sub("", snippet_match.group("snippet")).strip()[:1000]


async def search_lookup(query: str, *, allowed_domains: list[str], timeout_seconds: int, budget: int) -> list[dict]:
    if not query or not allowed_domains or budget <= 0:
        return []
    url = SEARCH_ENDPOINT.format(query=quote_plus(query))
    async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True, headers={"User-Agent": "Argus/1.0"}) as client:
        response = await client.get(url)
        response.raise_for_status()
    return parse_search_results(response.text, allowed_domains)[:budget]
