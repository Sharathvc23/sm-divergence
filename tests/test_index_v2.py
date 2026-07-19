"""NANDA Index v2 resolver — the two-hop resolve, and every claim-state edge."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from sm_divergence.discovery.index_v2 import NandaIndexV2Resolver

IDX = "https://index.example"
REG = "https://reg.example"


def _resolve_body(*, identifier: str | None = "abc", index_record: dict[str, Any] | None) -> dict[str, Any]:
    """The real NANDA Index v2 `/api/v1/resolve` shape: `registry_url` lives
    nested inside `index_record`, never at the top level (verified against
    the server's own `ResolveResponse`/`IndexRecord` TypeScript types)."""
    body: dict[str, Any] = {"locator": "urn:ai:agent:x"}
    if identifier is not None:
        body["identifier"] = identifier
    if index_record is not None:
        body["index_record"] = index_record
    return body


def _resolver(handler: Any, **kw: Any) -> NandaIndexV2Resolver:
    return NandaIndexV2Resolver(IDX, transport=httpx.MockTransport(handler), **kw)


def _two_hop(
    *,
    resolve: httpx.Response,
    record: httpx.Response | None = None,
) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/resolve":
            return resolve
        assert record is not None, f"unexpected hop-2 fetch to {request.url}"
        return record

    return handler


@pytest.mark.asyncio
async def test_two_hop_success() -> None:
    handler = _two_hop(
        resolve=httpx.Response(200, json=_resolve_body(index_record={"registry_url": REG})),
        record=httpx.Response(200, json={"endpoint": "https://agent.example/"}),
    )
    status, view = await _resolver(handler).resolve("urn:ai:agent:x")
    assert status == "present"
    assert view is not None and view.endpoint == "https://agent.example"


@pytest.mark.asyncio
async def test_hop1_404_is_absent() -> None:
    status, view = await _resolver(_two_hop(resolve=httpx.Response(404))).resolve("x")
    assert (status, view) == ("absent", None)


@pytest.mark.asyncio
async def test_hop1_soft_404_is_absent() -> None:
    handler = _two_hop(resolve=httpx.Response(200, json={"success": False, "error": "locator not found"}))
    assert await _resolver(handler).resolve("x") == ("absent", None)


@pytest.mark.asyncio
async def test_hop1_missing_index_record_is_error() -> None:
    handler = _two_hop(resolve=httpx.Response(200, json=_resolve_body(index_record=None)))
    assert await _resolver(handler).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_hop1_missing_registry_url_is_error() -> None:
    # index_record present but without registry_url — e.g. a malformed record
    handler = _two_hop(resolve=httpx.Response(200, json=_resolve_body(index_record={})))
    assert await _resolver(handler).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_hop1_null_registry_url_is_error() -> None:
    # registry_url is `string | null` in the real schema — null for e.g. DNS-AID
    # orgs, which this resolver's registry-fetch hop2 cannot follow. Documents
    # a known scope boundary rather than silently mishandling it.
    handler = _two_hop(resolve=httpx.Response(200, json=_resolve_body(index_record={"registry_url": None})))
    assert await _resolver(handler).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_hop1_missing_identifier_is_error() -> None:
    handler = _two_hop(
        resolve=httpx.Response(200, json=_resolve_body(identifier=None, index_record={"registry_url": REG}))
    )
    assert await _resolver(handler).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_hop1_non_200_is_error() -> None:
    assert await _resolver(_two_hop(resolve=httpx.Response(500))).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_hop2_404_is_absent() -> None:
    handler = _two_hop(
        resolve=httpx.Response(200, json=_resolve_body(index_record={"registry_url": REG})),
        record=httpx.Response(404),
    )
    assert await _resolver(handler).resolve("x") == ("absent", None)


@pytest.mark.asyncio
async def test_hop2_500_is_error() -> None:
    handler = _two_hop(
        resolve=httpx.Response(200, json=_resolve_body(index_record={"registry_url": REG})),
        record=httpx.Response(500),
    )
    assert await _resolver(handler).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_locator_for_maps_the_canonical_id() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/resolve":
            seen["locator"] = request.url.params.get("locator", "")
            return httpx.Response(200, json=_resolve_body(index_record={"registry_url": REG}))
        return httpx.Response(200, json={"endpoint": "https://agent.example"})

    resolver = _resolver(handler, locator_for=lambda aid: f"urn:ai:domain:acme.org:agent:{aid}")
    await resolver.resolve("alice")
    assert seen["locator"] == "urn:ai:domain:acme.org:agent:alice"


@pytest.mark.asyncio
async def test_hop2_uses_the_registry_url_and_record_path() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/resolve":
            return httpx.Response(200, json=_resolve_body(index_record={"registry_url": REG}))
        seen["hop2"] = str(request.url)
        return httpx.Response(200, json={"endpoint": "https://agent.example"})

    await _resolver(handler, record_path="/catalog/{id}.json").resolve("x")
    assert seen["hop2"] == "https://reg.example/catalog/abc.json"


def test_label_defaults_to_index_url_and_is_overridable() -> None:
    assert NandaIndexV2Resolver("https://idx.example/").label == "https://idx.example"
    assert NandaIndexV2Resolver("https://idx.example", label="nanda-index").label == "nanda-index"
