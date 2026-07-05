"""DidView — the identity layer's view type (an implementation of the core
``View`` contract). What a DID method resolves to, reduced to the one field that
must agree across methods: the agent's verification key.

The key is carried in ``did:key`` multibase form (``z…`` — multicodec ed25519-pub
+ base58btc), which both ``did:key`` DIDs and ``Ed25519VerificationKey2020``
``publicKeyMultibase`` fields use, so keys from different methods compare as plain
strings with no decoding.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

# Maps a canonical agent id to the DID it holds in a given method (identity
# correspondence — the caller's to define, like discovery's ``locator_for``).
DidFor = Callable[[str], str]

# The identity field name (also the kind of the finding a key disagreement makes).
KEY = "key"


def identity_did(agent_id: str) -> str:
    """Default ``did_for``: the watch id already *is* the DID for this method."""
    return agent_id


@dataclass(frozen=True)
class DidView:
    """One DID method's claim about an agent's verification key.

    ``key`` — the Ed25519 verification key in ``did:key`` multibase form
    (``z…``), or ``None`` when the method served a document with no usable key
    (which contributes nothing — an unreadable key is not a disagreement).
    """

    key: str | None = None

    def comparable(self) -> Mapping[str, str | None]:
        return {KEY: self.key}
