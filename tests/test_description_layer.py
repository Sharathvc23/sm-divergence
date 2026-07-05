"""The self-description as a corroborated layer — supersession, agent
equivocation, omission, staleness, and the HTTP distribution resolver.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from sm_divergence import (
    HttpDescriptionResolver,
    build_self_description,
    corroborate_descriptions,
    reconcile_descriptions,
    verify_self_description,
)
from sm_divergence.identity.selfdesc import SelfDescription

ENDPOINTS = ["https://acme.example/agents/acme"]


def _priv() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _sd(private_key: bytes, *, seq: int, aliases: dict[str, str]) -> SelfDescription:
    bundle = build_self_description(aliases, ENDPOINTS, private_key, seq=seq)
    sd = verify_self_description(bundle)
    assert sd is not None
    return sd


# ── reconcile: supersession + equivocation ───────────────────


def test_agreement_no_findings_and_canonical() -> None:
    signer = _priv()
    sd = _sd(signer, seq=5, aliases={"web": "did:web:acme.org"})
    r = reconcile_descriptions("acme", {"a": sd, "b": sd})
    assert r.findings == []
    assert r.canonical is not None and r.canonical.seq == 5


def test_supersession_highest_seq_wins() -> None:
    signer = _priv()
    old = _sd(signer, seq=3, aliases={"web": "did:web:old.example"})
    new = _sd(signer, seq=5, aliases={"web": "did:web:acme.org"})
    r = reconcile_descriptions("acme", {"stale-src": old, "fresh-src": new})
    assert r.canonical is not None and r.canonical.seq == 5
    assert r.canonical.alias("web") == "did:web:acme.org"
    # the source behind the top seq is flagged, but does not poison the winner
    assert [f.kind for f in r.findings] == ["stale_description"]
    assert r.findings[0].detail == {"stale_on": ["stale-src"], "current_seq": 5}


def test_agent_equivocation_same_seq_different_content() -> None:
    """The headline: the same key signed two different descriptions at the same
    seq — key compromise or a lying agent. Correspondence fails closed."""
    signer = _priv()
    a = _sd(signer, seq=5, aliases={"web": "did:web:acme.org"})
    b = _sd(signer, seq=5, aliases={"web": "did:web:attacker.example"})
    r = reconcile_descriptions("acme", {"src-a": a, "src-b": b})
    assert [f.kind for f in r.findings] == ["agent_equivocation"]
    assert r.findings[0].detail == {"seq": 5, "sources": ["src-a", "src-b"]}
    assert r.canonical is None  # fail closed


def test_same_seq_same_content_is_replication_not_equivocation() -> None:
    signer = _priv()
    sd = _sd(signer, seq=5, aliases={"web": "did:web:acme.org"})
    r = reconcile_descriptions("acme", {"a": sd, "b": sd})
    assert r.findings == [] and r.canonical is not None


def test_omission_of_the_description_itself() -> None:
    signer = _priv()
    sd = _sd(signer, seq=5, aliases={"web": "did:web:acme.org"})
    r = reconcile_descriptions("acme", {"has-it": sd, "hides-it": None})
    kinds = sorted(f.kind for f in r.findings)
    assert kinds == ["omission"]
    assert r.canonical is not None  # one honest source still yields the canonical


def test_no_descriptions_anywhere_is_empty() -> None:
    r = reconcile_descriptions("acme", {})
    assert r.canonical is None and r.findings == []


# ── HTTP distribution resolver ───────────────────────────────


def _transport(handler: Any) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_http_resolver_present_absent_error() -> None:
    signer = _priv()
    bundle = build_self_description({"web": "did:web:acme.org"}, ENDPOINTS, signer, seq=2)

    present = HttpDescriptionResolver(
        "https://a.example", transport=_transport(lambda r: httpx.Response(200, json=bundle))
    )
    status, sd = await present.resolve("acme")
    assert status == "present" and sd is not None and sd.seq == 2

    absent = HttpDescriptionResolver("https://a.example", transport=_transport(lambda r: httpx.Response(404)))
    assert await absent.resolve("acme") == ("absent", None)

    bad = HttpDescriptionResolver(
        "https://a.example",
        transport=_transport(lambda r: httpx.Response(200, json={"subject": "did:key:z", "signature": "x"})),
    )
    assert await bad.resolve("acme") == ("error", None)  # served but unverifiable → no claim


@pytest.mark.asyncio
async def test_corroborate_descriptions_end_to_end() -> None:
    signer = _priv()
    real = build_self_description({"web": "did:web:acme.org"}, ENDPOINTS, signer, seq=5)
    forged = build_self_description({"web": "did:web:attacker.example"}, ENDPOINTS, signer, seq=5)

    a = HttpDescriptionResolver(
        "https://a.example", transport=_transport(lambda r: httpx.Response(200, json=real)), label="a"
    )
    b = HttpDescriptionResolver(
        "https://b.example", transport=_transport(lambda r: httpx.Response(200, json=forged)), label="b"
    )

    result = await corroborate_descriptions([a, b], ["acme"])
    rec = result["acme"]
    assert [f.kind for f in rec.findings] == ["agent_equivocation"]
    assert rec.canonical is None
