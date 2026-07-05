"""DidKeyResolver — resolve a ``did:key`` offline (the self-certifying root).

A ``did:key`` *is* the key: no network, no document, nothing to trust. It is the
authoritative anchor a ``did:web`` (or Universal Resolver) claim is corroborated
against — if another method serves a different key for the same agent, that
method is stale, hijacked, or lying.
"""

from __future__ import annotations

from sm_resolver import Status

from .views import DidFor, DidView, identity_did


def key_from_did_key(did: str) -> str | None:
    """The multibase key of a ``did:key`` (the ``z…`` after the prefix), or None
    if the string is not an Ed25519-style ``did:key``."""
    prefix = "did:key:"
    if not did.startswith(prefix):
        return None
    multibase = did[len(prefix) :]
    return multibase if multibase.startswith("z") else None


class DidKeyResolver:
    """Resolve a canonical agent id's ``did:key`` to its key, offline.

    ``did_for`` maps the id to the agent's ``did:key`` (default: the id already
    is the DID). If the mapped value is not a ``did:key``, this resolver makes no
    claim (``error``) — it only speaks for the ``did:key`` method.
    """

    def __init__(self, *, did_for: DidFor = identity_did, label: str | None = None) -> None:
        self.did_for = did_for
        self._label = label or "did:key"

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, DidView | None]:
        key = key_from_did_key(self.did_for(agent_id))
        if key is None:
            return "error", None
        return "present", DidView(key=key)
