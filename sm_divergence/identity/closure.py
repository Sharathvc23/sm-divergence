"""Alias closure — "resolve FROM the identity, verify BACK to it", made normative.

A self-description proves the agent *claims* alias N on source R; it does not
prove R agrees. Drive a resolver blindly from a claimed alias and a malicious
agent can name a victim's alias: the resolver fetches the victim's record, and
the diff manufactures a divergence that discredits the honest source or the
victim. The rule that prevents it: **a record fetched via a claimed alias that
does not bind back to the same did:key contributes no claim — never a
divergence** (axiom 3's no-laundering, extended to correspondence).

Wrap a resolver whose target came from a self-asserted alias in
``AliasClosureResolver``; supply the layer's bind-back predicate (identity:
``binds_by_key``; discovery: ``sm_divergence.discovery.binds_by_did``).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Generic

from sm_resolver import Resolver, Status, ViewT

from .didkey import key_from_did_key
from .views import DidView

# canonical agent id -> the did:key it is expected to bind back to (or None).
ExpectedDid = Callable[[str], str | None]


class AliasClosureResolver(Generic[ViewT]):
    """Wrap ``inner`` (a resolver aimed via a self-asserted alias) so a resolved
    view that does not bind back to the expected ``did:key`` becomes an ``error``
    (no claim), never a divergence."""

    def __init__(
        self,
        inner: Resolver[ViewT],
        expected_did: ExpectedDid,
        binds: Callable[[ViewT, str], bool],
        *,
        label: str | None = None,
    ) -> None:
        self._inner = inner
        self._expected_did = expected_did
        self._binds = binds
        self._label = label or inner.label

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, ViewT | None]:
        status, view = await self._inner.resolve(agent_id)
        if status == "present" and view is not None:
            did = self._expected_did(agent_id)
            if did is None or not self._binds(view, did):
                return "error", None  # doesn't bind back to the identity — no claim
        return status, view


def binds_by_key(view: DidView, expected_did: str) -> bool:
    """Identity bind-back: the resolved method's key must equal the root
    ``did:key``'s key (both in multibase form)."""
    return view.key is not None and view.key == key_from_did_key(expected_did)
