"""Shared Ed25519 / ``did:key`` / JCS primitives — the self-certifying substrate.

Used by the discovery layer's verified-DID adapter and the identity layer's
self-description. Behind the ``attestation`` extra (``cryptography``, ``base58``,
``jcs``); every function raises a clear error if the extra is absent, so the base
install still runs the crypto-free checks (omission, endpoint, multibase key).

A ``did:key`` *is* the public key, so everything here verifies offline — no
network, no external trust.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any

try:
    import base58
    import jcs  # type: ignore[import-untyped]
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    _HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - exercised only without the extra
    _HAVE_CRYPTO = False

_ED25519_MULTICODEC = b"\xed\x01"
_EXTRA = "requires the 'attestation' extra: pip install sm-divergence[attestation]"


def _require() -> None:
    if not _HAVE_CRYPTO:
        raise RuntimeError(_EXTRA)


def canonical(obj: Mapping[str, Any]) -> bytes:
    """RFC 8785 (JCS) canonical bytes — byte-identical for signer and verifier."""
    _require()
    result: bytes = jcs.canonicalize(obj)
    return result


def pubkey_from_did_key(did: str) -> bytes | None:
    """The 32-byte Ed25519 public key a ``did:key`` encodes, or None."""
    _require()
    if not did.startswith("did:key:z"):
        return None
    try:
        raw = base58.b58decode(did[len("did:key:z") :])
    except Exception:
        return None
    if len(raw) != 34 or raw[:2] != _ED25519_MULTICODEC:
        return None
    return bytes(raw[2:])


def did_key_from_pubkey(pubkey: bytes) -> str:
    """The ``did:key`` for an Ed25519 public key (multicodec + base58btc)."""
    _require()
    encoded: str = base58.b58encode(_ED25519_MULTICODEC + pubkey).decode()
    return "did:key:z" + encoded


def public_from_private(private_key: bytes) -> bytes:
    """The 32-byte Ed25519 public key for a 32-byte private key."""
    _require()
    pub: bytes = (
        Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return pub


def sign(private_key: bytes, message: bytes) -> str:
    """Base64 Ed25519 signature over ``message`` with a 32-byte private key."""
    _require()
    return base64.b64encode(Ed25519PrivateKey.from_private_bytes(private_key).sign(message)).decode()


def verify(pubkey: bytes, message: bytes, sig_b64: str) -> bool:
    """True iff ``sig_b64`` is a valid Ed25519 signature of ``message``. Never raises."""
    _require()
    try:
        Ed25519PublicKey.from_public_bytes(pubkey).verify(base64.b64decode(sig_b64), message)
        return True
    except (InvalidSignature, Exception):
        return False
