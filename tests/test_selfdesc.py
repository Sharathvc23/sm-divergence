"""Signed portable-identity self-description (draft §8) — verification, and the
payoff: correspondence proven by the agent's signature drives the resolvers.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from sm_divergence import (
    SelfDescription,
    build_self_description,
    signed_alias_for,
    verified_descriptions,
    verify_self_description,
)

ALIASES = {"nest": "acme", "nanda": "urn:ai:domain:acme.org:agent:acme", "web": "did:web:acme.org"}
ENDPOINTS = ["https://acme.example/agents/acme", "https://acme.example/agentfacts.json"]


def _raw_private() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


@pytest.fixture
def signer() -> bytes:
    return _raw_private()


def _bundle(private_key: bytes, **kw: Any) -> dict[str, Any]:
    kw.setdefault("seq", 1)
    return build_self_description(ALIASES, ENDPOINTS, private_key, **kw)


# ── build / verify roundtrip ─────────────────────────────────


def test_build_verify_roundtrip(signer: bytes) -> None:
    sd = verify_self_description(_bundle(signer))
    assert isinstance(sd, SelfDescription)
    assert sd.alias("nanda") == "urn:ai:domain:acme.org:agent:acme"
    assert sd.alias("web") == "did:web:acme.org"
    assert sd.endpoints == tuple(ENDPOINTS)
    assert sd.alias("unknown") is None


def test_bundle_matches_paper_schema(signer: bytes) -> None:
    bundle = _bundle(signer)
    assert bundle["version"] == "self-description/0.1"
    assert bundle["subject"].startswith("did:key:z")
    assert set(bundle) == {"version", "subject", "seq", "aliases", "endpoints", "signature"}
    # verifies against the key inside it, offline
    assert verify_self_description(bundle) is not None


# ── adversarial: signature binds every field ─────────────────


def test_tampered_alias_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["aliases"]["web"] = "did:web:attacker.example"
    assert verify_self_description(bundle) is None


def test_tampered_endpoint_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["endpoints"][0] = "https://attacker.example"
    assert verify_self_description(bundle) is None


def test_swapped_subject_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer)
    other = build_self_description(ALIASES, ENDPOINTS, _raw_private(), seq=1)
    bundle["subject"] = other["subject"]
    assert verify_self_description(bundle) is None


def test_wrong_version_rejected(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["version"] = "self-description/9.9"
    assert verify_self_description(bundle) is None


def test_seq_is_carried_and_signed(signer: bytes) -> None:
    sd = verify_self_description(_bundle(signer, seq=7))
    assert sd is not None and sd.seq == 7


def test_tampered_seq_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer, seq=3)
    bundle["seq"] = 99  # replay as a newer seq
    assert verify_self_description(bundle) is None


def test_non_int_seq_rejected(signer: bytes) -> None:
    bundle = _bundle(signer, seq=1)
    bundle["seq"] = "1"
    assert verify_self_description(bundle) is None


@pytest.mark.parametrize(
    "bundle",
    [None, "str", {}, {"subject": "did:key:z", "signature": ""}, {"version": "self-description/0.1", "signature": "x"}],
)
def test_malformed_returns_none(bundle: Any) -> None:
    assert verify_self_description(bundle) is None


def test_non_string_alias_values_rejected(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["aliases"]["bad"] = 123  # not a str
    # signature no longer matches AND the shape is invalid — either way, None
    assert verify_self_description(bundle) is None


def test_non_string_endpoint_rejected(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["endpoints"].append(123)
    assert verify_self_description(bundle) is None


# ── the payoff: signed correspondence drives resolvers ───────


def test_signed_alias_for_uses_verified_aliases(signer: bytes) -> None:
    """A did_for/locator_for built from verified self-descriptions returns the
    agent's SIGNED name per namespace — correspondence proven, not configured."""
    sds = verified_descriptions({"acme": _bundle(signer)})
    web_did_for = signed_alias_for(sds, "web")
    nanda_locator_for = signed_alias_for(sds, "nanda")
    assert web_did_for("acme") == "did:web:acme.org"
    assert nanda_locator_for("acme") == "urn:ai:domain:acme.org:agent:acme"


def test_signed_alias_for_falls_back_when_unverified() -> None:
    """No verified description (or a garbage bundle) → fall back to the id itself,
    so an unsigned/forged self-description cannot silently redirect a resolver."""
    sds = verified_descriptions({"acme": {"subject": "did:key:z", "signature": "forged"}})
    assert sds == {}
    did_for = signed_alias_for(sds, "web")
    assert did_for("acme") == "acme"  # fallback = identity


def test_signed_alias_for_falls_back_for_missing_namespace(signer: bytes) -> None:
    sds = verified_descriptions({"acme": _bundle(signer)})
    assert signed_alias_for(sds, "no-such-namespace")("acme") == "acme"
