"""Signed portable-identity self-description — the agent asserts who it is.

Corroboration across differently-named sources needs to know that ``NEST:x``,
``NANDA:urn:…:x`` and ``did:web:acme.org`` are the same agent (draft §8's
*identity correspondence*). The library cannot infer that; today a caller
supplies the mapping (``locator_for`` / ``did_for``), which is configuration to
be *trusted*. A self-description moves the mapping INSIDE the identity: the agent
signs a bundle asserting its own aliases (its name in each namespace) and service
endpoints, with its ``did:key``. Verify it offline (a ``did:key`` is the key),
and the correspondence is *proven*, not configured.

Divergence then upgrades from "do these sources agree with each other?" to "do
these sources agree with what the identity SIGNED about itself?" — the strongest
check, because a source that diverges now contradicts the agent's own signature.

Bundle shape (draft §8 — flat; the signature is a member, over the JCS of every
other member)::

    {
      "version": "self-description/0.1",
      "subject": "did:key:z6Mk…",
      "seq": 7,
      "aliases":   { "nest": "x", "nanda": "urn:ai:…:x", "web": "did:web:acme.org" },
      "endpoints": [ "https://…/agents/x", "https://…" ],
      "signature": "<base64 Ed25519 over the JCS of all other members>"
    }

``seq`` is a monotonic counter the agent bumps each time it re-issues. Fix for
replay: a signed-but-superseded description stays validly signed forever, so
without an order a replayed old one launders a stale endpoint onto the
"strongest evidence" path. ``seq`` gives supersession — highest wins — and, at
equal ``seq`` with differing bytes, *agent equivocation*. There is no expiry:
freshness is by supersession, so a verifier needs no clock. See
``description_layer`` for reconciling descriptions collected from multiple
sources.

Requires the ``attestation`` extra (Ed25519 / did:key / JCS).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .. import _signing
from .views import DidFor, identity_did

SELF_DESCRIPTION_VERSION = "self-description/0.1"


@dataclass(frozen=True)
class SelfDescription:
    """A verified self-description: the agent's signed aliases + endpoints, at a
    monotonic ``seq`` (higher supersedes lower)."""

    subject: str
    seq: int
    aliases: Mapping[str, str]
    endpoints: tuple[str, ...]

    def alias(self, namespace: str) -> str | None:
        """The agent's signed name in ``namespace`` (e.g. ``nest``, ``nanda``, ``web``)."""
        return self.aliases.get(namespace)

    def content_key(self) -> str:
        """A stable digest of the SUBSTANTIVE claims (subject + aliases + endpoints)
        — two descriptions at the same ``seq`` with different content keys are the
        agent equivocating."""
        return json.dumps(
            {
                "subject": self.subject,
                "aliases": dict(sorted(self.aliases.items())),
                "endpoints": sorted(self.endpoints),
            },
            sort_keys=True,
        )


def _descriptor(subject: str, seq: int, aliases: Mapping[str, str], endpoints: Sequence[str]) -> dict[str, Any]:
    """The signed members, in a deterministic shape (JCS re-sorts anyway)."""
    return {
        "version": SELF_DESCRIPTION_VERSION,
        "subject": subject,
        "seq": int(seq),
        "aliases": dict(sorted(aliases.items())),
        "endpoints": list(endpoints),
    }


def build_self_description(
    aliases: Mapping[str, str],
    endpoints: Sequence[str],
    private_key: bytes,
    *,
    seq: int,
) -> dict[str, Any]:
    """A signed self-description bundle for the agent holding ``private_key`` (32
    raw Ed25519 bytes). The ``subject`` is derived from the key, so the signer and
    the subject are guaranteed identical. ``seq`` is the agent's monotonic counter
    — bump it on every re-issue so a replayed old description is detectably
    superseded. The signature covers the JCS of every other member (draft §8)."""
    subject = _signing.did_key_from_pubkey(_signing.public_from_private(private_key))
    bundle = _descriptor(subject, seq, aliases, endpoints)
    bundle["signature"] = _signing.sign(private_key, _signing.canonical(bundle))
    return bundle


def _str_map(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            return None
    return dict(value)


def _str_list(value: Any) -> list[str] | None:
    if not isinstance(value, list):
        return None
    for v in value:
        if not isinstance(v, str):
            return None
    return list(value)


def verify_self_description(bundle: Any) -> SelfDescription | None:
    """Verify a bundle's signature against the key its ``subject`` encodes.
    Returns the ``SelfDescription`` or None. Never raises.

    Offline: the ``did:key`` is the verification key, so nothing the (possibly
    hostile) sources say is trusted — only the agent's own signature. There is no
    freshness check; supersession by ``seq`` is the freshness discipline (draft
    §8), so a verifier consults no clock.
    """
    if not isinstance(bundle, dict):
        return None
    signature = bundle.get("signature")
    if not isinstance(signature, str) or not signature:
        return None
    if bundle.get("version") != SELF_DESCRIPTION_VERSION:
        return None
    subject = bundle.get("subject")
    seq = bundle.get("seq")
    if not isinstance(subject, str) or not isinstance(seq, int) or isinstance(seq, bool):
        return None
    aliases = _str_map(bundle.get("aliases"))
    endpoints = _str_list(bundle.get("endpoints"))
    if aliases is None or endpoints is None:
        return None

    pub = _signing.pubkey_from_did_key(subject)
    if pub is None:
        return None
    signed = {k: v for k, v in bundle.items() if k != "signature"}
    if not _signing.verify(pub, _signing.canonical(signed), signature):
        return None
    return SelfDescription(subject=subject, seq=seq, aliases=aliases, endpoints=tuple(endpoints))


def verified_descriptions(bundles: Mapping[str, Any]) -> dict[str, SelfDescription]:
    """Verify a ``{canonical_id: bundle}`` map, keeping only the ones that verify —
    the input to ``signed_alias_for``."""
    out: dict[str, SelfDescription] = {}
    for canonical_id, bundle in bundles.items():
        sd = verify_self_description(bundle)
        if sd is not None:
            out[canonical_id] = sd
    return out


def signed_alias_for(
    descriptions: Mapping[str, SelfDescription],
    namespace: str,
    *,
    fallback: DidFor = identity_did,
) -> DidFor:
    """Build a ``did_for`` / ``locator_for`` backed by verified self-descriptions.

    Maps a canonical agent id to the alias the agent SIGNED for ``namespace``,
    falling back (default: the id itself) when there is no verified description or
    no such alias. Wire it into any resolver — ``DidWebResolver(did_for=…)``,
    ``NandaIndexV2Resolver(locator_for=…)`` — so each source's name is proven, not
    configured.
    """

    def _for(agent_id: str) -> str:
        sd = descriptions.get(agent_id)
        if sd is not None:
            alias = sd.alias(namespace)
            if alias is not None:
                return alias
        return fallback(agent_id)

    return _for
