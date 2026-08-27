"""The signed Corroboration Record (draft §9) — build, content-address, verify."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from sm_resolver import Claim, Finding, SweepResult

from sm_divergence import (
    DivergenceDetector,
    build_corroboration_record,
    sign_sweep,
    verify_corroboration_record,
)
from sm_divergence._signing import corr_digest, did_key_from_pubkey, public_from_private
from sm_divergence.discovery.views import RecordView

A = "https://registry-a.example"
B = "https://registry-b.example"


def _sweeper_key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _divergent_sweep() -> SweepResult[RecordView]:
    claims = [
        Claim(A, None, "present", RecordView(endpoint="https://real.example"), 1_751_600_000.0, "present"),
        Claim(B, None, "present", RecordView(endpoint="https://evil.example"), 1_751_600_000.0, "present"),
    ]
    finding = Finding(
        "endpoint", "x", {"field": "endpoint", "values": {A: "https://real.example/", B: "https://evil.example/"}}
    )
    return SweepResult("x", "DIVERGENT", 1_751_600_000.0, 60.0, claims, [finding])


def test_record_has_paper_shape_and_roundtrips() -> None:
    key = _sweeper_key()
    record = build_corroboration_record(_divergent_sweep(), sweeper_private_key=key)

    assert set(record) == {
        "version",
        "record_id",
        "subject",
        "observed_at",
        "staleness_window_s",
        "verdict",
        "claims",
        "findings",
        "sweeper",
        "signature",
    }
    assert record["version"] == "corroboration/0.2"
    assert record["verdict"] == "DIVERGENT"
    assert record["subject"] == {"agent_id": "x", "did": None}
    assert record["observed_at"] == "2025-07-04T03:33:20Z"
    assert record["staleness_window_s"] == 60  # int, not float
    assert record["sweeper"] == did_key_from_pubkey(public_from_private(key))
    assert verify_corroboration_record(record) is True


def test_record_id_is_the_corr_digest() -> None:
    record = build_corroboration_record(_divergent_sweep(), sweeper_private_key=_sweeper_key())
    body = {k: v for k, v in record.items() if k not in ("record_id", "signature")}
    assert record["record_id"] == corr_digest(body)


def test_tampering_breaks_verification() -> None:
    record = build_corroboration_record(_divergent_sweep(), sweeper_private_key=_sweeper_key())
    tampered = {**record, "verdict": "AGREE"}
    assert verify_corroboration_record(tampered) is False  # record_id no longer matches


def test_signature_swap_breaks_verification() -> None:
    record = build_corroboration_record(_divergent_sweep(), sweeper_private_key=_sweeper_key())
    # keep a valid record_id but drop the signature's meaning
    forged = {**record, "signature": "AAAA"}
    assert verify_corroboration_record(forged) is False


def test_trusted_sweeper_pinning() -> None:
    record = build_corroboration_record(_divergent_sweep(), sweeper_private_key=_sweeper_key())
    assert verify_corroboration_record(record, trusted_sweeper=record["sweeper"]) is True
    assert verify_corroboration_record(record, trusted_sweeper="did:key:zSomeoneElse") is False


def test_subject_did_from_did_for() -> None:
    record = build_corroboration_record(
        _divergent_sweep(), sweeper_private_key=_sweeper_key(), did_for=lambda a: "did:key:zSUBJECT"
    )
    assert record["subject"] == {"agent_id": "x", "did": "did:key:zSUBJECT"}
    assert verify_corroboration_record(record) is True


def test_claims_include_error_entries_for_audit() -> None:
    claims = [
        Claim(A, None, "present", RecordView(endpoint="https://x.example"), 1_751_600_000.0, "present"),
        Claim(B, None, "error", None, 1_751_600_000.0, "error"),
    ]
    result: SweepResult[RecordView] = SweepResult("x", "INSUFFICIENT", 1_751_600_000.0, 0.0, claims, [])
    record = build_corroboration_record(result, sweeper_private_key=_sweeper_key())
    statuses = [c["status"] for c in record["claims"]]
    assert "error" in statuses  # error claim preserved
    assert record["verdict"] == "INSUFFICIENT"
    assert verify_corroboration_record(record) is True


@pytest.mark.asyncio
async def test_sign_sweep_emits_one_record_per_subject() -> None:
    class _Canned:
        def __init__(self, label: str, ep: str) -> None:
            self._label = label
            self._ep = ep

        @property
        def label(self) -> str:
            return self._label

        async def resolve(self, agent_id: str) -> tuple[str, RecordView]:
            return "present", RecordView(endpoint=self._ep)

    det: DivergenceDetector = DivergenceDetector(
        [_Canned("a", "https://x"), _Canned("b", "https://y")],  # type: ignore[list-item]
        staleness_window_s=30.0,
    )
    results = await det.check(["one", "two"], observed_at=1_751_600_000.0)
    records = sign_sweep(results, sweeper_private_key=_sweeper_key())
    assert len(records) == 2  # a record per subject, whatever the verdict
    assert all(verify_corroboration_record(r) for r in records)
    assert {r["subject"]["agent_id"] for r in records} == {"one", "two"}


# ── record version gate (draft -01 §10 rule 7) ──────────────


def _resigned_with_version(record: dict, version: str, key: bytes) -> dict:
    """Rebuild a record under a different `version`, correctly signed — so a
    rejection is attributable to the version and not to a broken signature."""
    from sm_divergence._signing import canonical, sign

    body = {k: v for k, v in record.items() if k not in ("record_id", "signature")}
    body["version"] = version
    signed = {**body, "record_id": corr_digest(body)}
    signed["signature"] = sign(key, canonical(signed))
    return signed


def test_a_record_with_an_unrecognised_version_is_rejected() -> None:
    # Correctly signed and content-addressed, but a shape this verifier does not
    # know. Without the gate it verifies silently and the version string is
    # decoration.
    key = _sweeper_key()
    record = _resigned_with_version(
        build_corroboration_record(_divergent_sweep(), sweeper_private_key=key), "corroboration/9.9", key
    )
    assert verify_corroboration_record(record) is False


def test_the_previous_record_version_is_still_accepted() -> None:
    # Gate on a SET, never equality: records issued before the current revision
    # remain verifiable, or the bump silently invalidates every one of them.
    key = _sweeper_key()
    record = _resigned_with_version(
        build_corroboration_record(_divergent_sweep(), sweeper_private_key=key), "corroboration/0.1", key
    )
    assert verify_corroboration_record(record) is True


def test_a_missing_version_is_rejected() -> None:
    key = _sweeper_key()
    base = build_corroboration_record(_divergent_sweep(), sweeper_private_key=key)
    body = {k: v for k, v in base.items() if k not in ("record_id", "signature", "version")}
    from sm_divergence._signing import canonical, sign

    signed = {**body, "record_id": corr_digest(body)}
    signed["signature"] = sign(key, canonical(signed))
    assert verify_corroboration_record(signed) is False


def test_records_are_built_at_the_current_version() -> None:
    record = build_corroboration_record(_divergent_sweep(), sweeper_private_key=_sweeper_key())
    assert record["version"] == "corroboration/0.2"
