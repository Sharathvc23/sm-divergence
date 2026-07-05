"""Signed portable-identity self-description — verification, freshness, and the
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

NOW = 1_751_600_000.0
ALIASES = {"nest": "acme", "nanda": "urn:ai:domain:acme.org:agent:acme", "web": "did:web:acme.org"}
SERVICES = {"discovery": "https://acme.example/agents/acme", "capability": "https://acme.example/agentfacts.json"}


def _raw_private() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


@pytest.fixture
def signer() -> bytes:
    return _raw_private()


def _bundle(private_key: bytes, **kw: Any) -> dict[str, Any]:
    kw.setdefault("now", NOW)
    kw.setdefault("seq", 1)
    return build_self_description(ALIASES, SERVICES, private_key, **kw)


# ── build / verify roundtrip ─────────────────────────────────


def test_build_verify_roundtrip(signer: bytes) -> None:
    sd = verify_self_description(_bundle(signer), now=NOW + 60)
    assert isinstance(sd, SelfDescription)
    assert sd.alias("nanda") == "urn:ai:domain:acme.org:agent:acme"
    assert sd.alias("web") == "did:web:acme.org"
    assert sd.service("discovery") == "https://acme.example/agents/acme"
    assert sd.alias("unknown") is None


def test_did_is_derived_from_the_signing_key(signer: bytes) -> None:
    bundle = _bundle(signer)
    assert bundle["descriptor"]["did"].startswith("did:key:z")
    # verifies against the key inside it, offline
    assert verify_self_description(bundle, now=NOW) is not None


# ── adversarial: signature binds every field ─────────────────


def test_tampered_alias_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["descriptor"]["aliases"]["web"] = "did:web:attacker.example"
    assert verify_self_description(bundle, now=NOW) is None


def test_tampered_service_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["descriptor"]["services"]["discovery"] = "https://attacker.example"
    assert verify_self_description(bundle, now=NOW) is None


def test_tampered_expiry_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer, ttl_s=300)
    bundle["descriptor"]["expires_at"] += 999_999
    assert verify_self_description(bundle, now=NOW) is None


def test_swapped_did_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer)
    other = build_self_description(ALIASES, SERVICES, _raw_private(), seq=1, now=NOW)
    bundle["descriptor"]["did"] = other["descriptor"]["did"]
    assert verify_self_description(bundle, now=NOW) is None


def test_seq_is_carried_and_signed(signer: bytes) -> None:
    sd = verify_self_description(_bundle(signer, seq=7), now=NOW)
    assert sd is not None and sd.seq == 7


def test_tampered_seq_breaks_signature(signer: bytes) -> None:
    bundle = _bundle(signer, seq=3)
    bundle["descriptor"]["seq"] = 99  # replay as a newer seq
    assert verify_self_description(bundle, now=NOW) is None


def test_non_int_seq_rejected(signer: bytes) -> None:
    bundle = _bundle(signer, seq=1)
    bundle["descriptor"]["seq"] = "1"
    assert verify_self_description(bundle, now=NOW) is None


def test_expired_is_rejected(signer: bytes) -> None:
    assert verify_self_description(_bundle(signer, ttl_s=300), now=NOW + 301) is None


@pytest.mark.parametrize(
    "bundle",
    [None, "str", {}, {"descriptor": {}, "sig": "x"}, {"descriptor": {"did": "did:key:z"}, "sig": ""}],
)
def test_malformed_returns_none(bundle: Any) -> None:
    assert verify_self_description(bundle, now=NOW) is None


def test_non_string_alias_values_rejected(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["descriptor"]["aliases"]["bad"] = 123  # not a str
    # signature no longer matches AND the shape is invalid — either way, None
    assert verify_self_description(bundle, now=NOW) is None


# ── the payoff: signed correspondence drives resolvers ───────


def test_signed_alias_for_uses_verified_aliases(signer: bytes) -> None:
    """A did_for/locator_for built from verified self-descriptions returns the
    agent's SIGNED name per namespace — correspondence proven, not configured."""
    sds = verified_descriptions({"acme": _bundle(signer)}, now=NOW)
    web_did_for = signed_alias_for(sds, "web")
    nanda_locator_for = signed_alias_for(sds, "nanda")
    assert web_did_for("acme") == "did:web:acme.org"
    assert nanda_locator_for("acme") == "urn:ai:domain:acme.org:agent:acme"


def test_signed_alias_for_falls_back_when_unverified() -> None:
    """No verified description (or a garbage bundle) → fall back to the id itself,
    so an unsigned/forged self-description cannot silently redirect a resolver."""
    sds = verified_descriptions({"acme": {"descriptor": {}, "sig": "forged"}}, now=NOW)
    assert sds == {}
    did_for = signed_alias_for(sds, "web")
    assert did_for("acme") == "acme"  # fallback = identity


def test_signed_alias_for_falls_back_for_missing_namespace(signer: bytes) -> None:
    sds = verified_descriptions({"acme": _bundle(signer)}, now=NOW)
    assert signed_alias_for(sds, "no-such-namespace")("acme") == "acme"
