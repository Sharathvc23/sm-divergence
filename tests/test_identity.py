"""The identity layer — DID-method resolvers and key divergence across methods.

The headline case: a ``did:web`` that serves a DIFFERENT key than the agent's
self-certifying ``did:key`` root is a ``key`` divergence — the second layer on
the same core, proving the seam generalizes past discovery.
"""

from __future__ import annotations

import httpx
import pytest
from _sweep import kinds

from sm_divergence import (
    Corroborator,
    DidKeyResolver,
    DidView,
    DidWebResolver,
    UniversalResolverResolver,
)
from sm_divergence.identity.didweb import did_web_url, key_from_did_document

# Two distinct Ed25519 did:key multibase values (shape only; not real keys).
KEY_A = "z6MkAAAArootkeyAAAA"
KEY_B = "z6MkBBBBimposterBBBB"


def _did_doc(multibase: str) -> dict[str, object]:
    return {
        "id": "did:web:example.com",
        "verificationMethod": [
            {"type": "Ed25519VerificationKey2020", "publicKeyMultibase": multibase},
        ],
    }


def _transport(handler: object) -> httpx.MockTransport:
    return httpx.MockTransport(handler)  # type: ignore[arg-type]


# ── did:key (offline root) ───────────────────────────────────


@pytest.mark.asyncio
async def test_did_key_resolves_offline() -> None:
    r = DidKeyResolver()
    assert await r.resolve(f"did:key:{KEY_A}") == ("present", DidView(key=KEY_A))


@pytest.mark.asyncio
async def test_non_did_key_makes_no_claim() -> None:
    assert await DidKeyResolver().resolve("did:web:example.com") == ("error", None)


# ── did:web (fetched) ────────────────────────────────────────


def test_did_web_url_mapping() -> None:
    assert did_web_url("did:web:example.com") == "https://example.com/.well-known/did.json"
    assert did_web_url("did:web:example.com:a:b") == "https://example.com/a/b/did.json"
    assert did_web_url("did:web:example.com%3A3000") == "https://example.com:3000/.well-known/did.json"
    assert did_web_url("did:key:z6Mk") is None


def test_key_from_did_document() -> None:
    assert key_from_did_document(_did_doc(KEY_A)) == KEY_A
    assert key_from_did_document({"verificationMethod": []}) is None
    assert key_from_did_document({}) is None


@pytest.mark.asyncio
async def test_did_web_present() -> None:
    r = DidWebResolver(transport=_transport(lambda req: httpx.Response(200, json=_did_doc(KEY_A))))
    status, view = await r.resolve("did:web:example.com")
    assert status == "present"
    assert view == DidView(key=KEY_A)


@pytest.mark.asyncio
async def test_did_web_404_is_absent() -> None:
    r = DidWebResolver(transport=_transport(lambda req: httpx.Response(404)))
    assert await r.resolve("did:web:example.com") == ("absent", None)


@pytest.mark.asyncio
async def test_did_web_unreachable_is_error() -> None:
    def boom(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    r = DidWebResolver(transport=_transport(boom))
    assert await r.resolve("did:web:example.com") == ("error", None)


@pytest.mark.asyncio
async def test_did_web_document_without_key_is_no_claim() -> None:
    r = DidWebResolver(transport=_transport(lambda req: httpx.Response(200, json={"verificationMethod": []})))
    assert await r.resolve("did:web:example.com") == ("error", None)


# ── Universal Resolver ───────────────────────────────────────


@pytest.mark.asyncio
async def test_universal_resolver_unwraps_did_document() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert "/1.0/identifiers/" in request.url.path
        return httpx.Response(200, json={"didDocument": _did_doc(KEY_A), "didResolutionMetadata": {}})

    r = UniversalResolverResolver("https://resolver.example", transport=_transport(handler))
    status, view = await r.resolve("did:web:example.com")
    assert (status, view) == ("present", DidView(key=KEY_A))


# ── key divergence across methods (the payoff) ───────────────


@pytest.mark.asyncio
async def test_did_web_key_diverges_from_did_key_root() -> None:
    """ADVERSARIAL: the root did:key says KEY_A; a hijacked did:web serves
    KEY_B. Corroborating the two methods for the same agent flags a ``key``
    divergence — the identity-layer analogue of endpoint tampering."""
    agent = "acme"
    did_key = DidKeyResolver(did_for=lambda a: f"did:key:{KEY_A}", label="did:key")
    did_web = DidWebResolver(
        did_for=lambda a: "did:web:acme.example",
        transport=_transport(lambda req: httpx.Response(200, json=_did_doc(KEY_B))),
        label="did:web",
    )
    results = await Corroborator([did_key, did_web]).check([agent])
    found = [f for r in results for f in r.findings]
    assert [f.kind for f in found] == ["key"]
    assert found[0].detail == {"field": "key", "values": {"did:key": KEY_A, "did:web": KEY_B}}


@pytest.mark.asyncio
async def test_matching_keys_no_divergence() -> None:
    agent = "acme"
    did_key = DidKeyResolver(did_for=lambda a: f"did:key:{KEY_A}", label="did:key")
    did_web = DidWebResolver(
        did_for=lambda a: "did:web:acme.example",
        transport=_transport(lambda req: httpx.Response(200, json=_did_doc(KEY_A))),
        label="did:web",
    )
    results = await Corroborator([did_key, did_web]).check([agent])
    assert kinds(results) == []
    assert next(r.verdict for r in results if r.agent_id == agent) == "AGREE"
