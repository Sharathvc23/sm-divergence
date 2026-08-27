"""Registry-operator identity — binding a source label to an operator's key.

A ``Resolver`` is identified only by ``label`` (a URL). Subject, record and
sweeper all have keys; the source *as an operator* has none, so nothing a source
signs about itself can be checked. This is the operator analogue of
``selfdesc``: the operator signs the labels it operates, and possession of the
label proves the claim.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from sm_divergence import (
    OperatorDescription,
    build_operator_description,
    verify_operator_description,
)

LABEL = "https://registry.example"
LABELS = [LABEL, "https://registry.example/v2"]


def _raw_private() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


@pytest.fixture
def signer() -> bytes:
    return _raw_private()


def _bundle(private_key: bytes, **kw: Any) -> dict[str, Any]:
    kw.setdefault("seq", 1)
    return build_operator_description(LABELS, private_key, **kw)


def test_build_verify_roundtrip(signer: bytes) -> None:
    od = verify_operator_description(_bundle(signer), served_from=LABEL)
    assert isinstance(od, OperatorDescription)
    assert od.subject.startswith("did:key:z")
    assert od.seq == 1
    assert LABEL in od.labels


# ── the binding: possession of the label proves the claim ────


def test_description_served_from_an_unclaimed_label_is_rejected(signer: bytes) -> None:
    # A validly-signed description says nothing about a label it does not name.
    # Without this, any operator could sign a bundle listing someone else's
    # registry and be accepted as its operator.
    assert verify_operator_description(_bundle(signer), served_from="https://other.example") is None


def test_labels_are_matched_by_exact_equality(signer: bytes) -> None:
    # No normalisation: a trailing slash is a different label. Inferring
    # equivalence between URL spellings is how one source's naming convention
    # silently becomes authority over another's.
    assert verify_operator_description(_bundle(signer), served_from=LABEL + "/") is None


# ── regression tests for the verification skeleton ──────────
# These guard checks adapted from `selfdesc.verify_self_description`, which is
# existing verified code; the binding above is the behaviour driven out here.


def test_tampering_with_a_signed_member_breaks_verification(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["labels"] = [LABEL, "https://attacker.example"]
    assert verify_operator_description(bundle, served_from=LABEL) is None


def test_a_bundle_with_the_wrong_version_is_rejected(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["version"] = "operator-description/0.2"
    assert verify_operator_description(bundle, served_from=LABEL) is None


def test_a_subject_that_is_not_a_did_key_is_rejected(signer: bytes) -> None:
    bundle = _bundle(signer)
    bundle["subject"] = "did:web:registry.example"
    assert verify_operator_description(bundle, served_from=LABEL) is None


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"signature": ""}])
def test_malformed_input_returns_none_and_never_raises(bad: Any) -> None:
    assert verify_operator_description(bad, served_from=LABEL) is None


def test_seq_must_be_an_int_not_a_bool(signer: bytes) -> None:
    bundle = build_operator_description(LABELS, signer, seq=True)  # type: ignore[arg-type]
    assert verify_operator_description(bundle, served_from=LABEL) is None
