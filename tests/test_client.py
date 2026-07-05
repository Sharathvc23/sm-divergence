"""fetch_view against a mocked HTTP transport — present / absent / error."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from sm_divergence.discovery.client import fetch_view

REG = "https://registry.example"


def _client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_present_maps_endpoint() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/agents/x"
        return httpx.Response(200, json={"agent_id": "x", "endpoint": "https://x.example/"})

    async with _client(handler) as c:
        status, view = await fetch_view(c, REG, "x")
    assert status == "present"
    assert view is not None and view.endpoint == "https://x.example"  # trailing slash stripped


@pytest.mark.asyncio
async def test_hard_404_is_absent() -> None:
    async with _client(lambda r: httpx.Response(404, json={"detail": "not found"})) as c:
        status, view = await fetch_view(c, REG, "x")
    assert (status, view) == ("absent", None)


@pytest.mark.asyncio
async def test_soft_404_body_is_absent() -> None:
    async with _client(lambda r: httpx.Response(200, json={"success": False, "error": "Agent not found"})) as c:
        status, view = await fetch_view(c, REG, "x")
    assert (status, view) == ("absent", None)


@pytest.mark.asyncio
async def test_500_is_error_not_a_claim() -> None:
    async with _client(lambda r: httpx.Response(500, text="boom")) as c:
        status, view = await fetch_view(c, REG, "x")
    assert (status, view) == ("error", None)


@pytest.mark.asyncio
async def test_connection_failure_is_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("unreachable")

    async with _client(handler) as c:
        status, view = await fetch_view(c, REG, "x")
    assert (status, view) == ("error", None)


@pytest.mark.asyncio
async def test_custom_path_template() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v2/orgs/x"
        return httpx.Response(200, json={"endpoint": "https://x.example"})

    async with _client(handler) as c:
        status, _ = await fetch_view(c, REG, "x", path="/v2/orgs/{id}")
    assert status == "present"
