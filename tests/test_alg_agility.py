"""The record names its signature algorithm, and the name is bound to the key.

`signature` was documented as Ed25519 and the algorithm appeared nowhere in the
record. A verifier had to know out of band, and a second algorithm could not be
introduced without silently changing what every existing record meant.

The `did:key` in `sweeper` already encodes the key type in its multicodec prefix,
so the algorithm was always discoverable — it just was not stated. Stating it is
the easy half. The half that matters is binding it: an `alg` a verifier trusts
without checking it against the key is a downgrade vector, not agility.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from sm_resolver import Claim, Finding, SweepResult

from sm_divergence import (
    ALG_ED25519,
    build_corroboration_record,
    verify_corroboration_record,
)
from sm_divergence._signing import (
    alg_from_did_key,
    canonical,
    corr_digest,
    did_key_from_pubkey,
    public_from_private,
    sign,
)
from sm_divergence.discovery.views import RecordView

A = "https://registry-a.example"


def _key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _sweep() -> SweepResult[RecordView]:
    claims = [
        Claim(A, None, "present", RecordView(endpoint="https://one.example"), 1_751_600_000.0, "present"),
        Claim("b", None, "present", RecordView(endpoint="https://two.example"), 1_751_600_000.0, "present"),
    ]
    finding = Finding("endpoint", "x", {"field": "endpoint", "values": {A: "1", "b": "2"}})
    return SweepResult("x", "DIVERGENT", 1_751_600_000.0, 60.0, claims, [finding])


def _resign(record: dict, key: bytes, **overrides) -> dict:
    body = {k: v for k, v in record.items() if k not in ("record_id", "signature")}
    body.update(overrides)
    signed = {**body, "record_id": corr_digest(body)}
    signed["signature"] = sign(key, canonical(signed))
    return signed


def test_a_record_names_its_algorithm() -> None:
    record = build_corroboration_record(_sweep(), sweeper_private_key=_key())
    assert record["alg"] == ALG_ED25519
    assert verify_corroboration_record(record) is True


def test_an_unknown_algorithm_is_rejected() -> None:
    key = _key()
    record = _resign(build_corroboration_record(_sweep(), sweeper_private_key=key), key, alg="ES256")
    assert verify_corroboration_record(record) is False


def test_a_missing_algorithm_is_rejected() -> None:
    key = _key()
    base = build_corroboration_record(_sweep(), sweeper_private_key=key)
    body = {k: v for k, v in base.items() if k not in ("record_id", "signature", "alg")}
    signed = {**body, "record_id": corr_digest(body)}
    signed["signature"] = sign(key, canonical(signed))
    assert verify_corroboration_record(signed) is False


def test_a_sweeper_key_of_another_type_is_rejected() -> None:
    # A P-256 did:key. Rejected today by the key loader, before the algorithm
    # check is reached — noted because the name should not imply otherwise.
    key = _key()
    record = _resign(
        build_corroboration_record(_sweep(), sweeper_private_key=key),
        key,
        sweeper="did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169",
    )
    assert verify_corroboration_record(record) is False


def test_the_algorithm_is_derived_from_the_key_not_taken_from_the_record() -> None:
    # The half that matters, tested where it lives. A did:key states its own key
    # type in its multicodec prefix, and that is what `alg` must agree with.
    # Trusting the record's own `alg` would be a downgrade vector: it would let a
    # record claim one algorithm while the signature was made with another.
    #
    # Tested against the helper directly because the key loader currently rejects
    # non-Ed25519 keys first, so the binding cannot be reached through
    # verify_corroboration_record alone. When a second algorithm is added, this
    # is the function that must already be right.
    key = _key()
    ours = did_key_from_pubkey(public_from_private(key))
    assert alg_from_did_key(ours) == ALG_ED25519
    assert alg_from_did_key("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169") is None
    assert alg_from_did_key("did:web:example.com") is None
    assert alg_from_did_key("did:key:znot-base58!!") is None


def test_alg_is_covered_by_the_signature() -> None:
    # Editing alg without re-signing must break verification, or the binding is
    # decorative.
    record = build_corroboration_record(_sweep(), sweeper_private_key=_key())
    record["alg"] = "ES256"
    assert verify_corroboration_record(record) is False


def test_records_issued_before_alg_existed_still_verify() -> None:
    # corroboration/0.1 and 0.2 have no `alg`. Requiring it unconditionally would
    # invalidate every record already issued — the same failure the accepted-set
    # version gate exists to prevent, arriving through a different door.
    key = _key()
    pub = did_key_from_pubkey(public_from_private(key))
    body = {
        "version": "corroboration/0.2",
        "subject": {"agent_id": "x", "did": None},
        "observed_at": "2026-07-04T00:00:00Z",
        "staleness_window_s": 60,
        "verdict": "AGREE",
        "claims": [],
        "findings": [],
        "sweeper": pub,
    }
    signed = {**body, "record_id": corr_digest(body)}
    signed["signature"] = sign(key, canonical(signed))
    assert verify_corroboration_record(signed) is True


def test_a_current_record_without_alg_is_rejected() -> None:
    # The allowance is for old versions only. A 0.3 record must name it.
    key = _key()
    base = build_corroboration_record(_sweep(), sweeper_private_key=key)
    body = {k: v for k, v in base.items() if k not in ("record_id", "signature", "alg")}
    signed = {**body, "record_id": corr_digest(body)}
    signed["signature"] = sign(key, canonical(signed))
    assert signed["version"] == "corroboration/0.4"
    assert verify_corroboration_record(signed) is False


def test_an_old_record_that_names_a_wrong_alg_is_still_rejected() -> None:
    # Absent is tolerated for old versions; wrong is not.
    key = _key()
    pub = did_key_from_pubkey(public_from_private(key))
    body = {
        "version": "corroboration/0.2",
        "alg": "ES256",
        "subject": {"agent_id": "x", "did": None},
        "observed_at": "2026-07-04T00:00:00Z",
        "staleness_window_s": 60,
        "verdict": "AGREE",
        "claims": [],
        "findings": [],
        "sweeper": pub,
    }
    signed = {**body, "record_id": corr_digest(body)}
    signed["signature"] = sign(key, canonical(signed))
    assert verify_corroboration_record(signed) is False
