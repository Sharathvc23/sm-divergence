"""Answer Scope — a registry declaring, in advance, which fields it varies and
along which vantage class.

Declaration only: a scope names the AXIS a field varies on, never the mapping
from context to value. Signed by the operator key (`operator.py`) and bound to
the label it was served from, exactly as an operator description is.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from sm_divergence import (
    AnswerScope,
    build_answer_scope,
    verify_answer_scope,
)

LABEL = "https://registry.example"
SCOPES = [{"field": "endpoint", "vantage_class": "region"}]


def _raw_private() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


@pytest.fixture
def signer() -> bytes:
    return _raw_private()


def _bundle(private_key: bytes, scopes: Any = None, **kw: Any) -> dict[str, Any]:
    kw.setdefault("seq", 1)
    return build_answer_scope(LABEL, SCOPES if scopes is None else scopes, private_key, **kw)


def test_build_verify_roundtrip(signer: bytes) -> None:
    scope = verify_answer_scope(_bundle(signer), served_from=LABEL)
    assert isinstance(scope, AnswerScope)
    assert scope.seq == 1
    assert scope.varies("endpoint") == "region"
    assert scope.varies("did") is None


# ── the rules that stop a scope being a blanket excuse ───────


def test_a_non_occupiable_vantage_class_is_rejected(signer: bytes) -> None:
    # "tenant" is an attribute of the caller relationship, not of the
    # observation: a verifier cannot go and be a different tenant, so it could
    # only take the operator's word. Accepting it would mean reporting the
    # operator's own assertion back as evidence.
    bundle = _bundle(signer, [{"field": "endpoint", "vantage_class": "tenant"}])
    assert verify_answer_scope(bundle, served_from=LABEL) is None


def test_a_wildcard_vantage_class_is_rejected_even_if_explicitly_allowed(signer: bytes) -> None:
    # Defence in depth: widening `occupiable` is a deliberate act, and it must
    # not become a way to smuggle a catch-all past the grammar. The permissive
    # form is what turns a declared-scope mechanism into an attack surface, so
    # it is refused at the token level regardless of the allowed set.
    bundle = _bundle(signer, [{"field": "endpoint", "vantage_class": "*"}])
    assert verify_answer_scope(bundle, served_from=LABEL, occupiable=frozenset({"*"})) is None


def test_a_wildcard_field_is_rejected(signer: bytes) -> None:
    bundle = _bundle(signer, [{"field": "*", "vantage_class": "region"}])
    assert verify_answer_scope(bundle, served_from=LABEL) is None


def test_the_same_field_declared_twice_is_rejected(signer: bytes) -> None:
    # Overlapping scopes let the operator pick whichever applies after the fact.
    bundle = _bundle(
        signer,
        [
            {"field": "endpoint", "vantage_class": "region"},
            {"field": "endpoint", "vantage_class": "asn"},
        ],
    )
    assert verify_answer_scope(bundle, served_from=LABEL) is None


def test_more_scopes_than_the_cap_is_rejected(signer: bytes) -> None:
    bundle = _bundle(signer, [{"field": f"f{i}", "vantage_class": "region"} for i in range(17)])
    assert verify_answer_scope(bundle, served_from=LABEL) is None


def test_a_scope_served_from_an_unclaimed_label_is_rejected(signer: bytes) -> None:
    assert verify_answer_scope(_bundle(signer), served_from="https://other.example") is None


def test_widening_the_occupiable_set_is_explicit(signer: bytes) -> None:
    # A deployment may widen the set deliberately — never by accident.
    bundle = _bundle(signer, [{"field": "endpoint", "vantage_class": "tenant"}])
    assert verify_answer_scope(bundle, served_from=LABEL) is None
    widened = verify_answer_scope(bundle, served_from=LABEL, occupiable=frozenset({"tenant"}))
    assert widened is not None
    assert widened.varies("endpoint") == "tenant"


# ── declaring no variation is a positive statement ───────────


def test_an_empty_scope_list_verifies_and_asserts_no_variation(signer: bytes) -> None:
    # Distinct from publishing nothing: silence is ambiguous between "does not
    # vary" and "has never heard of this".
    scope = verify_answer_scope(_bundle(signer, []), served_from=LABEL)
    assert scope is not None
    assert scope.declares_no_variation is True
    assert scope.varies("endpoint") is None


def test_a_populated_scope_does_not_assert_no_variation(signer: bytes) -> None:
    scope = verify_answer_scope(_bundle(signer), served_from=LABEL)
    assert scope is not None
    assert scope.declares_no_variation is False


# ── regression tests for the verification skeleton ──────────


def test_tampering_with_a_signed_member_breaks_verification(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["scopes"] = [{"field": "did", "vantage_class": "region"}]
    assert verify_answer_scope(bundle, served_from=LABEL) is None


def test_a_bundle_with_the_wrong_version_is_rejected(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["version"] = "answer-scope/0.2"
    assert verify_answer_scope(bundle, served_from=LABEL) is None


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"signature": ""}])
def test_malformed_input_returns_none_and_never_raises(bad: Any) -> None:
    assert verify_answer_scope(bad, served_from=LABEL) is None


def test_a_scope_entry_with_extra_keys_is_rejected(signer: bytes) -> None:
    bundle = _bundle(signer, [{"field": "endpoint", "vantage_class": "region", "note": "x"}])
    assert verify_answer_scope(bundle, served_from=LABEL) is None
