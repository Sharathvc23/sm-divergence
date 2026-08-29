"""The evidence slot for prior publication.

`scope_violation` may not be raised without evidence that the scope predates the
observation it contradicts, and this stack has no witnessed history to provide
it. That restraint is right, but leaving the interface undefined means a
deployment that DOES have such a history has no interoperable way to record the
proof, and no verifier can check one.

So the envelope is defined here and the mechanism is not. What can be checked
without knowing the mechanism is the shape and the binding: that the proof names
a mechanism, and that it is bound to the exact scope bytes being relied on.
Whether the proof itself is valid is the mechanism's business.
"""

from __future__ import annotations

import pytest

from sm_divergence import verify_history_proof

DIGEST = "a" * 64
OTHER = "b" * 64


def _proof(**overrides) -> dict:
    p = {
        "type": "org.example.scitt-inclusion",
        "statement_digest": DIGEST,
        "proof": {"log_id": "x", "inclusion": "..."},
    }
    p.update(overrides)
    return p


def test_a_well_formed_proof_bound_to_the_expected_scope_is_accepted() -> None:
    assert verify_history_proof(_proof(), expected_digest=DIGEST) is True


def test_a_proof_bound_to_a_different_scope_is_rejected() -> None:
    # The binding is the point. A proof about some other scope is evidence about
    # something else, however valid it is in its own terms.
    assert verify_history_proof(_proof(), expected_digest=OTHER) is False


def test_a_missing_digest_is_rejected() -> None:
    p = _proof()
    del p["statement_digest"]
    assert verify_history_proof(p, expected_digest=DIGEST) is False


def test_an_unnamespaced_mechanism_is_rejected() -> None:
    # This document seeds no mechanisms, so every type is a third party's and
    # must be namespaced. A bare name would claim a reservation that does not
    # exist.
    assert verify_history_proof(_proof(type="scitt"), expected_digest=DIGEST) is False


def test_a_missing_or_empty_mechanism_is_rejected() -> None:
    assert verify_history_proof(_proof(type=""), expected_digest=DIGEST) is False
    p = _proof()
    del p["type"]
    assert verify_history_proof(p, expected_digest=DIGEST) is False


def test_a_missing_proof_payload_is_rejected() -> None:
    p = _proof()
    del p["proof"]
    assert verify_history_proof(p, expected_digest=DIGEST) is False


@pytest.mark.parametrize("bad", [None, [], "x", 7, {}])
def test_malformed_input_is_rejected_and_never_raises(bad: object) -> None:
    assert verify_history_proof(bad, expected_digest=DIGEST) is False


def test_accepting_the_envelope_is_not_accepting_the_proof() -> None:
    # Stated as a test so the boundary cannot be misread: the payload is opaque
    # here, and a caller that treats a True from this function as "the scope
    # predates the observation" has misunderstood what was checked.
    assert verify_history_proof(_proof(proof={"anything": "unverified"}), expected_digest=DIGEST) is True
