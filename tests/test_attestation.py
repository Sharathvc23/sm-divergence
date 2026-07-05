"""Signed-record adapter — verified DID extraction and its adversarial edges."""

from __future__ import annotations

import base64
from typing import Any

import base58
import jcs
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sm_divergence.discovery.attestation import signed_record_adapter, verified_did

_ED25519_MULTICODEC = b"\xed\x01"


def _did_key(pub: bytes) -> str:
    return "did:key:z" + base58.b58encode(_ED25519_MULTICODEC + pub).decode()


def _sign_record(sk: Ed25519PrivateKey, subject: str, endpoint: str) -> dict[str, Any]:
    pub = sk.public_key().public_bytes_raw()
    record = {"agent_id": subject, "did": _did_key(pub), "endpoint": endpoint}
    sig = sk.sign(jcs.canonicalize(record))
    return {"record": record, "sig": base64.b64encode(sig).decode()}


@pytest.fixture
def signer() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def test_verified_did_roundtrip(signer: Ed25519PrivateKey) -> None:
    att = _sign_record(signer, "x", "https://x.example")
    assert verified_did(att) == att["record"]["did"]


def test_tampered_endpoint_breaks_verification(signer: Ed25519PrivateKey) -> None:
    att = _sign_record(signer, "x", "https://x.example")
    att["record"]["endpoint"] = "https://attacker.example"
    assert verified_did(att) is None


def test_swapped_did_breaks_verification(signer: Ed25519PrivateKey) -> None:
    att = _sign_record(signer, "x", "https://x.example")
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    att["record"]["did"] = _did_key(other)
    assert verified_did(att) is None


@pytest.mark.parametrize("bad", [None, "str", {}, {"record": {}, "sig": ""}, {"record": {"did": 1}, "sig": "x"}])
def test_malformed_returns_none(bad: Any) -> None:
    assert verified_did(bad) is None


def test_adapter_extracts_endpoint_and_verified_did(signer: Ed25519PrivateKey) -> None:
    att = _sign_record(signer, "x", "https://x.example")
    record = {"agent_id": "x", "endpoint": "https://x.example", "attestation": att}
    view = signed_record_adapter()(record)
    assert view.endpoint == "https://x.example"
    assert view.did == att["record"]["did"]


def test_adapter_rejects_subject_mismatch(signer: Ed25519PrivateKey) -> None:
    # A valid attestation for 'x' dressed onto a record for 'y' → no DID.
    att = _sign_record(signer, "x", "https://x.example")
    record = {"agent_id": "y", "endpoint": "https://y.example", "attestation": att}
    view = signed_record_adapter()(record)
    assert view.endpoint == "https://y.example"
    assert view.did is None


def test_adapter_without_attestation_has_no_did() -> None:
    view = signed_record_adapter()({"agent_id": "x", "endpoint": "https://x.example"})
    assert view.endpoint == "https://x.example"
    assert view.did is None
