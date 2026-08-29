"""A declared finding must be re-derivable from the record.

`declared: true, declaration_version: 7` says a scope with sequence 7 was
allegedly matched. It does not say WHICH `{field, vantage_class}` rule was
matched, or which scope bundle sequence 7 refers to. A third party holding the
record cannot reproduce the decision, which contradicts the property this format
asserts throughout: verifiable from recorded bytes.

The record therefore carries the scopes a sweep used. The digest is mandatory and
binds the decision to specific bytes; the scope contents are optional, because
embedding every bundle bloats every record while a verifier that already holds
the bundle needs only the digest to know it is the right one.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from sm_resolver import Claim, Finding, SweepResult

from sm_divergence import (
    build_answer_scope,
    build_corroboration_record,
    scope_evidence,
    verify_answer_scope,
    verify_corroboration_record,
)
from sm_divergence._signing import corr_digest
from sm_divergence.discovery.views import RecordView

A = "https://registry-a.example"
B = "https://registry-b.example"


def _key() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def _bundle_and_scope(label: str, seq: int = 7):
    bundle = build_answer_scope(label, [{"field": "endpoint", "vantage_class": "region"}], _key(), seq=seq)
    scope = verify_answer_scope(bundle, served_from=label)
    assert scope is not None
    return bundle, scope


def _sweep() -> SweepResult[RecordView]:
    claims = [Claim(A, "region:eu", "present", RecordView(endpoint="https://eu.example"), 1_751_600_000.0, "present")]
    finding = Finding(
        "source_equivocation",
        "x",
        {"source": A, "field": "endpoint", "values": {"region:eu": "1", "region:us": "2"}},
        declared=True,
        declaration_version="7",
    )
    return SweepResult("x", "DIVERGENT", 1_751_600_000.0, 60.0, claims, [finding])


def test_a_record_carries_the_scopes_the_sweep_used() -> None:
    bundle, scope = _bundle_and_scope(A)
    record = build_corroboration_record(_sweep(), sweeper_private_key=_key(), answer_scopes=scope_evidence({A: scope}))
    (entry,) = record["answer_scopes"]
    assert entry["label"] == A
    assert entry["seq"] == 7
    assert entry["subject"] == scope.subject
    assert entry["scopes"] == [{"field": "endpoint", "vantage_class": "region"}]
    assert verify_corroboration_record(record) is True


def test_the_entry_binds_to_specific_bytes() -> None:
    # The digest is what makes the evidence more than a restatement: a verifier
    # holding a bundle can tell whether it is the one that was used.
    bundle, scope = _bundle_and_scope(A)
    (entry,) = scope_evidence({A: scope})
    assert entry["scope_digest"] == corr_digest(
        {"version": bundle["version"], "subject": scope.subject, "label": A, "seq": 7, "scopes": entry["scopes"]}
    )


def test_a_declared_finding_can_be_matched_to_its_scope() -> None:
    # The re-derivation path: a finding names its source and the seq it matched;
    # the record names the scope with that label and seq, and what it permitted.
    _, scope = _bundle_and_scope(A)
    record = build_corroboration_record(_sweep(), sweeper_private_key=_key(), answer_scopes=scope_evidence({A: scope}))
    finding = record["findings"][0]
    assert finding["declared"] is True
    match = [
        e
        for e in record["answer_scopes"]
        if e["label"] == finding["detail"]["source"] and str(e["seq"]) == finding["declaration_version"]
    ]
    assert len(match) == 1
    assert match[0]["scopes"] == [{"field": "endpoint", "vantage_class": "region"}]


def test_a_sweep_with_no_scopes_carries_an_empty_list() -> None:
    # Present and empty, not absent. "No scope was used" and "this implementation
    # does not record scopes" are different facts.
    record = build_corroboration_record(_sweep(), sweeper_private_key=_key())
    assert record["answer_scopes"] == []


def test_scope_evidence_is_ordered_by_label() -> None:
    _, sa = _bundle_and_scope(A)
    _, sb = _bundle_and_scope(B, seq=3)
    assert [e["label"] for e in scope_evidence({B: sb, A: sa})] == sorted([A, B])


def test_the_scopes_are_covered_by_the_record_signature() -> None:
    _, scope = _bundle_and_scope(A)
    record = build_corroboration_record(_sweep(), sweeper_private_key=_key(), answer_scopes=scope_evidence({A: scope}))
    record["answer_scopes"][0]["scopes"] = [{"field": "endpoint", "vantage_class": "asn"}]
    assert verify_corroboration_record(record) is False
