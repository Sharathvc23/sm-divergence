"""The Corroboration Record — a signed, content-addressed attestation that a
corroboration sweep ran and what it concluded (draft §9).

The kernel's ``SweepResult`` is plain, unsigned data: a verdict, the claims, the
findings. A record *seals* one sweep result for one subject: it stamps the
sweeper's ``did:key``, content-addresses the body (``record_id`` = CORR-DIGEST),
and signs it. One record MUST be emitted for **every** ``(sweep, subject)`` pair,
whatever the verdict — the ``AGREE`` record is the positive attestation that the
checks ran, which a disagreement-only trail can never prove.

A record verifies offline: recompute the CORR-DIGEST, then check the signature
against the key the ``sweeper`` ``did:key`` encodes. It MAY additionally be
anchored in an append-only transparency log; that tier is out of scope here (the
base tier is the sweeper's self-attestation).

Record shape (draft §9 — ``signature`` is a member, over the JCS of every other
member; ``record_id`` is the CORR-DIGEST of every member except itself and
``signature``)::

    {
      "version": "corroboration/0.1",
      "record_id": "<hex CORR-DIGEST>",
      "subject": { "agent_id": "<id>", "did": "<did:key or null>" },
      "observed_at": "<RFC 3339 UTC, Z>",
      "staleness_window_s": <int>,
      "verdict": "AGREE" | "DIVERGENT" | "INSUFFICIENT",
      "claims":   [ { "source", "vantage", "status", "view", "outcome" }, … ],
      "findings": [ { "kind", "agent_id", "confirmation", "detail" }, … ],
      "sweeper": "did:key:z6Mk…",
      "signature": "<base64 Ed25519>"
    }

Requires the ``attestation`` extra (Ed25519 / did:key / JCS).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from sm_resolver import Claim, SweepResult, ViewT

from . import _signing

CORROBORATION_VERSION = "corroboration/0.1"

# agent_id → the subject's canonical did:key (or None when there is no verified
# identity for it). Defaults to "no did" — the record still attests the sweep.
DidFor = Callable[[str], str | None]


def _claim_entry(claim: Claim[ViewT]) -> dict[str, Any]:
    view = None if claim.view is None else dict(claim.view.comparable())
    return {
        "source": claim.source,
        "vantage": claim.vantage,
        "status": claim.status,
        "view": view,
        "outcome": claim.outcome,
    }


def build_corroboration_record(
    result: SweepResult[ViewT],
    *,
    sweeper_private_key: bytes,
    did_for: DidFor | None = None,
) -> dict[str, Any]:
    """Seal one ``SweepResult`` into a signed Corroboration Record.

    ``sweeper_private_key`` is 32 raw Ed25519 bytes; the ``sweeper`` ``did:key``
    is derived from it, so the signer and the attested party are identical.
    ``did_for`` supplies the subject's canonical ``did:key`` (default: none).
    ``claims`` includes ``error`` entries (excluded from the diff, kept for
    audit), and all timestamps/windows are whole integers so no JSON float enters
    a digest-bearing field.
    """
    sweeper = _signing.did_key_from_pubkey(_signing.public_from_private(sweeper_private_key))
    body: dict[str, Any] = {
        "version": CORROBORATION_VERSION,
        "subject": {"agent_id": result.agent_id, "did": did_for(result.agent_id) if did_for else None},
        "observed_at": _signing.rfc3339(result.observed_at),
        "staleness_window_s": int(result.staleness_window_s),
        "verdict": result.verdict,
        "claims": [_claim_entry(c) for c in result.claims],
        "findings": [f.to_dict() for f in result.findings],
        "sweeper": sweeper,
    }
    signed = {**body, "record_id": _signing.corr_digest(body)}
    signed["signature"] = _signing.sign(sweeper_private_key, _signing.canonical(signed))
    return signed


def sign_sweep(
    results: Iterable[SweepResult[ViewT]],
    *,
    sweeper_private_key: bytes,
    did_for: DidFor | None = None,
) -> list[dict[str, Any]]:
    """Seal every ``SweepResult`` of a sweep into a record — one per subject,
    whatever each verdict (draft §9 requires the ``AGREE`` records too)."""
    return [build_corroboration_record(r, sweeper_private_key=sweeper_private_key, did_for=did_for) for r in results]


def verify_corroboration_record(record: Any, *, trusted_sweeper: str | None = None) -> bool:
    """Verify a record offline: recompute ``record_id`` (CORR-DIGEST of the body
    minus ``record_id`` and ``signature``) and verify ``signature`` against the
    key ``sweeper`` encodes. If ``trusted_sweeper`` is given, the record's sweeper
    MUST equal it. Returns True iff both hold. Never raises."""
    if not isinstance(record, dict):
        return False
    signature = record.get("signature")
    record_id = record.get("record_id")
    sweeper = record.get("sweeper")
    if not isinstance(signature, str) or not signature or not isinstance(record_id, str):
        return False
    if not isinstance(sweeper, str):
        return False
    if trusted_sweeper is not None and sweeper != trusted_sweeper:
        return False
    body = {k: v for k, v in record.items() if k not in ("record_id", "signature")}
    if _signing.corr_digest(body) != record_id:
        return False
    pub = _signing.pubkey_from_did_key(sweeper)
    if pub is None:
        return False
    signed = {k: v for k, v in record.items() if k != "signature"}
    return _signing.verify(pub, _signing.canonical(signed), signature)
