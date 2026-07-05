"""Alias closure — a record reached via a self-asserted alias that does not bind
back to the agent's did:key contributes no claim, never a divergence.
"""

from __future__ import annotations

import pytest

from sm_divergence import (
    AliasClosureResolver,
    Corroborator,
    DidView,
    RecordView,
    binds_by_did,
    binds_by_key,
    key_from_did_key,
)
from sm_divergence.identity.views import DidView as _DidView  # noqa: F401  (import-shape check)

# A did:key and its multibase key.
DID = "did:key:z6MkACMErootkey"
KEY = key_from_did_key(DID)


class _CannedResolver:
    """Returns a fixed (status, view) — stands in for a resolver aimed at a
    self-asserted alias (whose target might be another agent's record)."""

    def __init__(self, label, status, view):
        self.label = label
        self._status = status
        self._view = view

    async def resolve(self, agent_id):
        return self._status, self._view


def _expect(_agent_id: str) -> str | None:
    return DID


# ── discovery bind-back (verified DID) ───────────────────────


def test_binds_by_did() -> None:
    assert binds_by_did(RecordView(endpoint="https://x", did=DID), DID) is True
    assert binds_by_did(RecordView(endpoint="https://x", did="did:key:zOTHER"), DID) is False
    assert binds_by_did(RecordView(endpoint="https://x", did=None), DID) is False  # no verified did → no bind


# ── identity bind-back (key matches the root did:key) ────────


def test_binds_by_key() -> None:
    assert binds_by_key(DidView(key=KEY), DID) is True
    assert binds_by_key(DidView(key="z6MkOTHER"), DID) is False
    assert binds_by_key(DidView(key=None), DID) is False


# ── the closure resolver ─────────────────────────────────────


@pytest.mark.asyncio
async def test_bound_record_passes_through() -> None:
    inner = _CannedResolver("nest", "present", RecordView(endpoint="https://real", did=DID))
    wrapped: AliasClosureResolver[RecordView] = AliasClosureResolver(inner, _expect, binds_by_did)
    assert await wrapped.resolve("acme") == ("present", RecordView(endpoint="https://real", did=DID))


@pytest.mark.asyncio
async def test_non_binding_record_becomes_no_claim() -> None:
    """The victim scenario: the agent claimed a victim's alias, so the resolver
    fetched the victim's record (bound to the VICTIM's did). It must contribute
    no claim — never a divergence against the victim."""
    victim = RecordView(endpoint="https://victim", did="did:key:zVICTIM")
    inner = _CannedResolver("nest", "present", victim)
    wrapped: AliasClosureResolver[RecordView] = AliasClosureResolver(inner, _expect, binds_by_did)
    assert await wrapped.resolve("acme") == ("error", None)


@pytest.mark.asyncio
async def test_no_expected_did_is_no_claim() -> None:
    inner = _CannedResolver("nest", "present", RecordView(endpoint="https://x", did=DID))
    wrapped: AliasClosureResolver[RecordView] = AliasClosureResolver(inner, lambda a: None, binds_by_did)
    assert await wrapped.resolve("acme") == ("error", None)


@pytest.mark.asyncio
async def test_absent_and_error_pass_through_unchanged() -> None:
    for status in ("absent", "error"):
        inner = _CannedResolver("nest", status, None)
        wrapped: AliasClosureResolver[RecordView] = AliasClosureResolver(inner, _expect, binds_by_did)
        assert await wrapped.resolve("acme") == (status, None)


@pytest.mark.asyncio
async def test_closure_prevents_manufactured_divergence() -> None:
    """Two honest sources agree on the victim; the attacker's aliased fetch of the
    victim's record is dropped by closure, so NO divergence is manufactured."""
    honest_a = _CannedResolver("src-a", "present", RecordView(endpoint="https://victim", did="did:key:zVICTIM"))
    honest_b = _CannedResolver("src-b", "present", RecordView(endpoint="https://victim", did="did:key:zVICTIM"))
    # attacker's resolver points at the victim's record but expects the attacker's did
    attacker_view = RecordView(endpoint="https://victim", did="did:key:zVICTIM")
    attacker = AliasClosureResolver(
        _CannedResolver("src-c", "present", attacker_view), _expect, binds_by_did, label="src-c"
    )
    results = await Corroborator([honest_a, honest_b, attacker]).check(["acme"])
    found = [f for r in results for f in r.findings]
    assert found == []  # closure dropped src-c's non-binding claim; no false divergence
    # two honest present claims agree, src-c became an error (no claim) → AGREE
    assert next(r.verdict for r in results if r.agent_id == "acme") == "AGREE"
