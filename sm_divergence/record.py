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
      "version": "corroboration/0.4",
      "alg": "EdDSA",
      "record_id": "<hex CORR-DIGEST>",
      "subject": { "agent_id": "<id>", "did": "<did:key or null>" },
      "observed_at": "<RFC 3339 UTC, Z>",
      "staleness_window_s": <int>,
      "verdict": "AGREE" | "DIVERGENT" | "INSUFFICIENT",
      "claims":   [ { "source", "vantage", "status", "view", "outcome" }, … ],
      "findings": [ { "kind", "agent_id", "confirmation",
                      "declared", "declaration_version", "detail" }, … ],
      "answer_scopes": [ { "label", "subject", "seq", "scope_digest",
                           "scopes" }, … ],
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

CORROBORATION_VERSION = "corroboration/0.4"

# Versions this build will verify. Gated on a SET, never on equality with
# CORROBORATION_VERSION: a record is evidence, and evidence issued before the
# current revision must stay verifiable — equality-gating would silently
# invalidate every record already in the wild on each bump. `0.2` adds
# `declared`/`declaration_version` to each finding; their absence in a `0.1`
# record reads as undeclared, which is the conservative interpretation.
ACCEPTED_RECORD_VERSIONS: frozenset[str] = frozenset(
    {"corroboration/0.1", "corroboration/0.2", "corroboration/0.3", CORROBORATION_VERSION}
)

# Versions issued before `alg` existed. Ed25519 is implied for these; the member
# is REQUIRED from corroboration/0.3 onward.
_PRE_ALG_VERSIONS: frozenset[str] = frozenset({"corroboration/0.1", "corroboration/0.2"})

# agent_id → the subject's canonical did:key (or None when there is no verified
# identity for it). Defaults to "no did" — the record still attests the sweep.
DidFor = Callable[[str], str | None]


def _claim_entry(claim: Claim[ViewT]) -> dict[str, Any]:
    view = None if claim.view is None else dict(claim.view.comparable())
    entry: dict[str, Any] = {
        "source": claim.source,
        "vantage": claim.vantage,
        "status": claim.status,
        "view": view,
        "outcome": claim.outcome,
    }
    binding = _binding_entry(claim)
    if binding is not None:
        entry["binding"] = binding
    return entry


def _binding_entry(claim: Claim[ViewT]) -> dict[str, Any] | None:
    """The claim's lease position, when its view exposes one (kernel SPEC §3b).
    Recorded so a `stale_binding` finding is re-derivable from the record: the
    finding names the sequences, and this is where a verifier checks them."""
    view = claim.view
    if view is None:
        return None
    method = getattr(view, "binding", None)
    if method is None:
        return None
    try:
        binding = method()
    except Exception:
        return None
    if binding is None:
        return None
    sequence = getattr(binding, "sequence", None)
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        return None
    return {"sequence": sequence, "scope": getattr(binding, "scope", None)}


def build_corroboration_record(
    result: SweepResult[ViewT],
    *,
    sweeper_private_key: bytes,
    did_for: DidFor | None = None,
    answer_scopes: list[dict[str, Any]] | None = None,
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
        "alg": _signing.ALG_ED25519,
        "subject": {"agent_id": result.agent_id, "did": did_for(result.agent_id) if did_for else None},
        "observed_at": _signing.rfc3339(result.observed_at),
        "staleness_window_s": int(result.staleness_window_s),
        "verdict": result.verdict,
        "claims": [_claim_entry(c) for c in result.claims],
        "findings": [f.to_dict() for f in result.findings],
        # Present and empty when no scope was used. "No scope applied" and "this
        # implementation does not record scopes" are different facts, and a
        # verifier that cannot tell them apart cannot know whether a record
        # without scopes is complete. See `licensing.scope_evidence`.
        "answer_scopes": answer_scopes if answer_scopes is not None else [],
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
    MUST equal it. The record's ``version`` MUST be one this build accepts
    (``ACCEPTED_RECORD_VERSIONS``) — a signature proves the bytes are intact, not
    that the shape is one this code understands, and verifying an unknown shape
    means reporting members it never read. Returns True iff all hold. Never
    raises."""
    if not isinstance(record, dict):
        return False
    if record.get("version") not in ACCEPTED_RECORD_VERSIONS:
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
    # The algorithm must agree with the key type the sweeper's did:key encodes.
    # Reading `alg` and trusting it would be a downgrade vector: a record could
    # claim one algorithm while the signature was made with another. The key is
    # authoritative; `alg` states the obligation rather than deciding it.
    #
    # `alg` is REQUIRED from corroboration/0.3. Records issued before it have no
    # such member and Ed25519 is implied — requiring it unconditionally would
    # invalidate every record already issued, which is the same failure
    # ACCEPTED_RECORD_VERSIONS exists to prevent.
    expected = _signing.alg_from_did_key(sweeper)
    if expected is None:
        return False
    alg = record.get("alg")
    if alg is None:
        if record.get("version") not in _PRE_ALG_VERSIONS:
            return False
    elif alg != expected:
        return False
    signed = {k: v for k, v in record.items() if k != "signature"}
    return _signing.verify(pub, _signing.canonical(signed), signature)
