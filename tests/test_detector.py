"""DivergenceDetector orchestration — fetch, diff, dedupe, emit."""

from __future__ import annotations

import httpx
import pytest

from sm_divergence import DivergenceDetector, Finding, check_once

A = "https://registry-a.example"
B = "https://registry-b.example"


def _routed(records: dict[str, dict[str, object] | int]) -> httpx.MockTransport:
    """records[hostname] → JSON body (present) or int status (e.g. 404)."""

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        aid = request.url.path.rsplit("/", 1)[-1]
        entry = records.get(host)
        if isinstance(entry, int):
            return httpx.Response(entry, json={"detail": "not found"})
        if entry is None:
            raise httpx.ConnectError("unreachable")
        return httpx.Response(200, json={"agent_id": aid, **entry})

    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _patch_client(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route the HttpByIdResolver's httpx.AsyncClient through a per-test transport
    (string registries are wrapped in HttpByIdResolver, which owns the client)."""
    import sm_divergence.discovery.http_by_id as http_by_id

    self_transport: dict[str, httpx.MockTransport] = {}

    orig = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        return orig(transport=self_transport["t"])

    monkeypatch.setattr(http_by_id.httpx, "AsyncClient", factory)
    _patch_client.transport = self_transport  # type: ignore[attr-defined]


def _install(transport: httpx.MockTransport) -> None:
    _patch_client.transport["t"] = transport  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_single_registry_is_noop() -> None:
    _install(_routed({"registry-a.example": {"endpoint": "https://x.example"}}))
    assert await check_once([A], ["x"]) == []


@pytest.mark.asyncio
async def test_agreement_no_findings() -> None:
    _install(
        _routed(
            {
                "registry-a.example": {"endpoint": "https://x.example"},
                "registry-b.example": {"endpoint": "https://x.example"},
            }
        )
    )
    assert await check_once([A, B], ["x"]) == []


@pytest.mark.asyncio
async def test_endpoint_divergence_detected() -> None:
    _install(
        _routed(
            {
                "registry-a.example": {"endpoint": "https://real.example"},
                "registry-b.example": {"endpoint": "https://attacker.example"},
            }
        )
    )
    findings = await check_once([A, B], ["x"])
    assert [f.kind for f in findings] == ["endpoint"]


@pytest.mark.asyncio
async def test_omission_detected() -> None:
    _install(_routed({"registry-a.example": {"endpoint": "https://x.example"}, "registry-b.example": 404}))
    findings = await check_once([A, B], ["x"])
    assert [f.kind for f in findings] == ["omission"]


@pytest.mark.asyncio
async def test_unreachable_registry_makes_no_claim() -> None:
    _install(_routed({"registry-a.example": {"endpoint": "https://x.example"}, "registry-b.example": None}))
    assert await check_once([A, B], ["x"]) == []


@pytest.mark.asyncio
async def test_on_finding_fires_once_per_finding() -> None:
    _install(
        _routed(
            {
                "registry-a.example": {"endpoint": "https://real.example"},
                "registry-b.example": {"endpoint": "https://attacker.example"},
            }
        )
    )
    emitted: list[Finding] = []
    det = DivergenceDetector([A, B], on_finding=emitted.append)
    first = await det.check(["x"])
    second = await det.check(["x"])
    assert [f.kind for f in first] == ["endpoint"]
    assert [f.kind for f in second] == ["endpoint"]  # still returned
    assert len(emitted) == 1  # but only emitted once


@pytest.mark.asyncio
async def test_duplicate_registries_deduped() -> None:
    _install(_routed({"registry-a.example": {"endpoint": "https://x.example"}}))
    det = DivergenceDetector([A, A, A])
    assert det.registries == [A]
    assert await det.check(["x"]) == []
