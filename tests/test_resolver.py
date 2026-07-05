"""The Resolver protocol + HttpByIdResolver, and mixing resolver types."""

from __future__ import annotations

import httpx
import pytest
from _sweep import kinds, verdict_of

from sm_divergence import DivergenceDetector, HttpByIdResolver, NandaIndexV2Resolver, Resolver

A = "https://registry-a.example"


def _transport(handler: object) -> httpx.MockTransport:
    return httpx.MockTransport(handler)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_http_resolver_present() -> None:
    def h(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/agents/x"
        return httpx.Response(200, json={"endpoint": "https://x.example/"})

    r = HttpByIdResolver(A, transport=_transport(h))
    status, view = await r.resolve("x")
    assert status == "present"
    assert view is not None and view.endpoint == "https://x.example"


@pytest.mark.asyncio
async def test_http_resolver_absent_and_error() -> None:
    absent = HttpByIdResolver(A, transport=_transport(lambda req: httpx.Response(404)))
    assert await absent.resolve("x") == ("absent", None)
    err = HttpByIdResolver(A, transport=_transport(lambda req: httpx.Response(503)))
    assert await err.resolve("x") == ("error", None)


def test_label_defaults_to_url_and_is_overridable() -> None:
    assert HttpByIdResolver("https://a.example/").label == "https://a.example"
    assert HttpByIdResolver("https://a.example", label="nest").label == "nest"


def test_resolver_types_expose_the_protocol_surface() -> None:
    # Both concrete resolvers expose the Resolver protocol surface (label + resolve).
    resolvers: list[Resolver] = [HttpByIdResolver(A), NandaIndexV2Resolver("https://idx.example")]
    for r in resolvers:
        assert isinstance(r.label, str)
        assert callable(r.resolve)


@pytest.mark.asyncio
async def test_detector_dedupes_by_label() -> None:
    r1 = HttpByIdResolver(A, label="same")
    r2 = HttpByIdResolver("https://other.example", label="same")
    det = DivergenceDetector([r1, r2])
    assert det.registries == ["same"]  # second dropped — a check needs two DISTINCT sources
    results = await det.check(["x"])
    assert kinds(results) == []
    assert verdict_of(results, "x") == "INSUFFICIENT"  # only one distinct resolver


@pytest.mark.asyncio
async def test_mixed_resolver_types_diverge() -> None:
    """A NEST-style by-id resolver and a NANDA Index resolver, compared uniformly."""

    def nest(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"endpoint": "https://real.example"})

    def nanda(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/resolve":
            return httpx.Response(200, json={"registry_url": "https://reg.example", "identifier": "x"})
        return httpx.Response(200, json={"endpoint": "https://attacker.example"})

    det = DivergenceDetector(
        [
            HttpByIdResolver("https://nest.example", transport=_transport(nest), label="nest"),
            NandaIndexV2Resolver("https://index.example", transport=_transport(nanda), label="nanda"),
        ]
    )
    results = await det.check(["x"])
    found = [f for r in results for f in r.findings]
    assert [f.kind for f in found] == ["endpoint"]
    # RFC 3986-normalized (empty path → "/")
    assert found[0].detail["values"] == {"nanda": "https://attacker.example/", "nest": "https://real.example/"}
