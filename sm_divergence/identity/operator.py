"""Registry-operator identity — the operator signs the labels it operates.

A ``Resolver`` is identified only by ``label`` (a URL). The subject has a key
(``selfdesc``), the served record can have one (``attestation``), and the sweeper
has one (``record``) — but the *source as an operator* has none. So nothing a
registry signs about its own behaviour can be checked: there is no key to check
it against.

This is the operator analogue of ``selfdesc``. The operator signs a bundle naming
the source labels it operates, with its ``did:key``; a sweeper that fetches the
bundle *from* one of those labels has the binding proven rather than configured.

Bundle shape (flat; the signature is a member, over the JCS of every other
member)::

    {
      "version": "operator-description/0.1",
      "subject": "did:key:z6Mk…",
      "seq": 3,
      "labels": [ "https://registry.example", "https://registry.example/v2" ],
      "signature": "<base64 Ed25519 over the JCS of all other members>"
    }

``seq`` is monotonic — highest wins — matching ``selfdesc``'s supersession
discipline, so a verifier needs no clock.

Requires the ``attestation`` extra (Ed25519 / did:key / JCS).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .. import _signing

OPERATOR_DESCRIPTION_VERSION = "operator-description/0.1"


@dataclass(frozen=True)
class OperatorDescription:
    """A verified operator description: the labels an operator signed for, at a
    monotonic ``seq`` (higher supersedes lower)."""

    subject: str
    seq: int
    labels: tuple[str, ...]


def _descriptor(subject: str, seq: int, labels: list[str]) -> dict[str, Any]:
    return {
        "version": OPERATOR_DESCRIPTION_VERSION,
        "subject": subject,
        "seq": seq,
        "labels": labels,
    }


def build_operator_description(
    labels: list[str],
    private_key: bytes,
    *,
    seq: int,
) -> dict[str, Any]:
    """A signed operator-description bundle for the operator holding
    ``private_key`` (32 raw Ed25519 bytes). The ``subject`` is derived from the
    key, so signer and subject are guaranteed identical. Bump ``seq`` on every
    re-issue so a replayed old description is detectably superseded."""
    subject = _signing.did_key_from_pubkey(_signing.public_from_private(private_key))
    bundle = _descriptor(subject, seq, list(labels))
    bundle["signature"] = _signing.sign(private_key, _signing.canonical(bundle))
    return bundle


def _str_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    for v in value:
        if not isinstance(v, str):
            return None
    return list(value)


def verify_operator_description(bundle: Any, *, served_from: str) -> OperatorDescription | None:
    """Verify a bundle's signature against the key its ``subject`` encodes, AND
    that it names ``served_from`` — the label it was fetched from.

    Both halves are required. A valid signature only proves *some* operator wrote
    the bundle; it says nothing about which labels that operator controls, so a
    bundle naming a registry it was not served from is worth nothing. Serving it
    at the label is what proves control, exactly as ``did:web`` resolution proves
    control of a domain by fetching from it.

    ``served_from`` is matched against ``labels`` by exact equality — no
    normalisation of scheme, case, port or trailing slash. Inferring equivalence
    between URL spellings is how one naming convention silently acquires
    authority over another; a label that should match must be spelled the same.

    Returns the ``OperatorDescription`` or None. Never raises."""
    if not isinstance(bundle, dict):
        return None
    signature = bundle.get("signature")
    if not isinstance(signature, str) or not signature:
        return None
    if bundle.get("version") != OPERATOR_DESCRIPTION_VERSION:
        return None
    subject = bundle.get("subject")
    seq = bundle.get("seq")
    if not isinstance(subject, str) or not isinstance(seq, int) or isinstance(seq, bool):
        return None
    labels = _str_list(bundle.get("labels"))
    if labels is None:
        return None

    pub = _signing.pubkey_from_did_key(subject)
    if pub is None:
        return None
    signed = {k: v for k, v in bundle.items() if k != "signature"}
    if not _signing.verify(pub, _signing.canonical(signed), signature):
        return None
    if served_from not in labels:
        return None
    return OperatorDescription(subject=subject, seq=seq, labels=tuple(labels))
