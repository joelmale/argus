"""List endpoints must answer with or without a trailing slash instead of redirecting.

A redirect from behind the Next.js proxy points at the backend's internal host
(http://backend:8000/...), which the browser cannot reach.
"""
import pytest


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/api/v1/assets", "/api/v1/scans", "/api/v1/findings"])
async def test_list_routes_do_not_redirect(api_client, admin_user, path):
    headers = {"Authorization": f"Bearer {admin_user['token']}"}
    for variant in (path, f"{path}/"):
        response = await api_client.get(variant, headers=headers, follow_redirects=False)
        assert response.status_code == 200, f"{variant} -> {response.status_code}"


@pytest.mark.asyncio
async def test_findings_filter_by_asset(api_client, admin_user):
    headers = {"Authorization": f"Bearer {admin_user['token']}"}
    response = await api_client.get("/api/v1/findings/", params={"asset_id": "00000000-0000-0000-0000-000000000000"}, headers=headers)
    assert response.status_code == 200 and response.json() == []
