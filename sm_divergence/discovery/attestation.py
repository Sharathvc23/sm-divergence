"""Optional: a record adapter that extracts a *verified* DID.

Endpoint and omission divergence need no crypto. The ``did`` divergence — two
registries serving records that claim different key identities — only means
something if each DID was actually proven, so this module verifies a signed,
self-certifying record before contributing its DID to the comparison.

Reference format (a common self-certifying-record convention, not tied to any
one registry):

    {
      "record": { ... , "did": "did:key:z6Mk...", "endpoint": "https://..." },
      "sig":    "<base64 Ed25519 signature over the JCS-canonical record>"
    }

The DID is verified against ITSELF: a ``did:key`` encodes the Ed25519 public
key, so the signature is checked with no external lookup. A record whose
signature doesn't verify (or whose subject doesn't match) contributes no DID.

Requires the ``attestation`` extra: ``pip install sm-divergence[attestation]``.
"""

from __future__ import annotations

from typing import Any

from .. import _signing
from .client import RecordAdapter
from .views import RecordView


def verified_did(attestation: Any) -> str | None:
    """The DID of a signed record iff its signature verifies against the key
    the DID itself encodes; else None. Never raises."""
    if not isinstance(attestation, dict):
        return None
    record = attestation.get("record")
    sig_b64 = attestation.get("sig")
    if not isinstance(record, dict) or not isinstance(sig_b64, str) or not sig_b64:
        return None
    did = record.get("did")
    if not isinstance(did, str):
        return None
    pub = _signing.pubkey_from_did_key(did)
    if pub is None:
        return None
    if not _signing.verify(pub, _signing.canonical(record), sig_b64):
        return None
    return did


def signed_record_adapter(
    endpoint_field: str = "endpoint",
    attestation_field: str = "attestation",
    *,
    require_subject_match: bool = True,
) -> RecordAdapter:
    """A ``RecordAdapter`` that maps a registry record to endpoint + VERIFIED DID.

    The DID is taken only from a valid attestation under ``attestation_field``.
    When ``require_subject_match`` is set (default), the attestation's
    ``record.agent_id`` must equal the outer record's — a registry can't dress
    one agent's record in another's valid attestation.
    """

    def _adapt(record: dict[str, Any]) -> RecordView:
        ep = record.get(endpoint_field)
        endpoint = str(ep).rstrip("/") if isinstance(ep, str) and ep else None

        did: str | None = None
        att = record.get(attestation_field)
        vdid = verified_did(att) if att is not None else None
        if vdid is not None:
            inner = att.get("record", {}) if isinstance(att, dict) else {}
            subject = inner.get("agent_id")
            outer = record.get("agent_id")
            if not require_subject_match or subject is None or outer is None or str(subject) == str(outer):
                did = vdid
        return RecordView(endpoint=endpoint, did=did)

    return _adapt
