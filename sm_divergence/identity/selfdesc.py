"""Signed portable-identity self-description — the agent asserts who it is.

Corroboration across differently-named sources needs to know that ``NEST:x``,
``NANDA:urn:…:x`` and ``did:web:acme.org`` are the same agent. The library cannot
infer that; today a caller supplies the mapping (``locator_for`` / ``did_for``),
which is configuration to be *trusted*. A self-description moves the mapping
INSIDE the identity: the agent signs a bundle asserting its own aliases (its name
in each namespace) and service endpoints, with its ``did:key``. Verify it offline
(a ``did:key`` is the key), and the correspondence is *proven*, not configured.

Divergence then upgrades from "do these sources agree with each other?" to "do
these sources agree with what the identity SIGNED about itself?" — the strongest
check, because a source that diverges now contradicts the agent's own signature.

Bundle shape (``{descriptor, sig}``)::

    {
      "descriptor": {
        "v": 1,
        "did": "did:key:z6Mk…",
        "seq": 5,
        "aliases":  { "nest": "x", "nanda": "urn:ai:…:x", "web": "did:web:acme.org" },
        "services": { "discovery": "https://…/agents/x", "capability": "https://…" },
        "issued_at": 1751600000,
        "expires_at": 1751686400
      },
      "sig": "<base64 Ed25519 over the JCS-canonical descriptor>"
    }

``seq`` is a monotonic counter the agent bumps each time it re-issues (Fix for
replay: a signed-but-superseded description stays validly signed forever, so
without an order a replayed old one launders a stale endpoint onto the
"strongest evidence" path). ``expires_at`` bounds freshness; ``seq`` gives
supersession — highest wins. See ``description_layer`` for reconciling
descriptions collected from multiple sources (and detecting *agent
equivocation*: two valid descriptions at the same ``seq`` with different
content).

Requires the ``attestation`` extra (Ed25519 / did:key / JCS).
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .. import _signing
from .views import DidFor, identity_did

SELF_DESCRIPTION_VERSION = 1
DEFAULT_TTL_S = 24 * 3600.0


@dataclass(frozen=True)
class SelfDescription:
    """A verified self-description: the agent's signed aliases + service endpoints,
    at a monotonic ``seq`` (higher supersedes lower)."""

    did: str
    seq: int
    aliases: Mapping[str, str]
    services: Mapping[str, str]
    issued_at: int
    expires_at: int

    def alias(self, namespace: str) -> str | None:
        """The agent's signed name in ``namespace`` (e.g. ``nest``, ``nanda``, ``web``)."""
        return self.aliases.get(namespace)

    def service(self, kind: str) -> str | None:
        """The agent's signed endpoint for ``kind`` (e.g. ``discovery``, ``capability``)."""
        return self.services.get(kind)

    def content_key(self) -> str:
        """A stable digest of the SUBSTANTIVE claims (did + aliases + services),
        excluding timestamps — two descriptions at the same ``seq`` with different
        content keys are the agent equivocating."""
        return json.dumps(
            {
                "did": self.did,
                "aliases": dict(sorted(self.aliases.items())),
                "services": dict(sorted(self.services.items())),
            },
            sort_keys=True,
        )


def build_self_description(
    aliases: Mapping[str, str],
    services: Mapping[str, str],
    private_key: bytes,
    *,
    seq: int,
    now: float | None = None,
    ttl_s: float | None = None,
) -> dict[str, Any]:
    """A signed self-description bundle for the agent holding ``private_key`` (32
    raw Ed25519 bytes). The descriptor's ``did`` is derived from the key, so the
    signer and the subject are guaranteed identical. ``seq`` is the agent's
    monotonic counter — bump it on every re-issue so a replayed old description
    is detectably superseded."""
    did = _signing.did_key_from_pubkey(_signing.public_from_private(private_key))
    ts = int(now if now is not None else time.time())
    descriptor: dict[str, Any] = {
        "v": SELF_DESCRIPTION_VERSION,
        "did": did,
        "seq": int(seq),
        "aliases": dict(sorted(aliases.items())),
        "services": dict(sorted(services.items())),
        "issued_at": ts,
        "expires_at": ts + int(ttl_s if ttl_s is not None else DEFAULT_TTL_S),
    }
    sig = _signing.sign(private_key, _signing.canonical(descriptor))
    return {"descriptor": descriptor, "sig": sig}


def _str_map(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict):
        return None
    for k, v in value.items():
        if not isinstance(k, str) or not isinstance(v, str):
            return None
    return dict(value)


def verify_self_description(bundle: Any, *, now: float | None = None) -> SelfDescription | None:
    """Verify a bundle's signature against the key its ``did`` encodes, then its
    freshness. Returns the ``SelfDescription`` or None. Never raises.

    Offline: the ``did:key`` is the verification key, so nothing the (possibly
    hostile) sources say is trusted — only the agent's own signature.
    """
    if not isinstance(bundle, dict):
        return None
    descriptor = bundle.get("descriptor")
    sig = bundle.get("sig")
    if not isinstance(descriptor, dict) or not isinstance(sig, str) or not sig:
        return None
    did = descriptor.get("did")
    seq = descriptor.get("seq")
    issued_at = descriptor.get("issued_at")
    expires_at = descriptor.get("expires_at")
    if not isinstance(did, str) or not isinstance(seq, int) or isinstance(seq, bool):
        return None
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        return None
    aliases = _str_map(descriptor.get("aliases"))
    services = _str_map(descriptor.get("services"))
    if aliases is None or services is None:
        return None

    pub = _signing.pubkey_from_did_key(did)
    if pub is None:
        return None
    if not _signing.verify(pub, _signing.canonical(descriptor), sig):
        return None
    current = now if now is not None else time.time()
    if current > expires_at:
        return None
    return SelfDescription(
        did=did, seq=seq, aliases=aliases, services=services, issued_at=issued_at, expires_at=expires_at
    )


def verified_descriptions(bundles: Mapping[str, Any], *, now: float | None = None) -> dict[str, SelfDescription]:
    """Verify a ``{canonical_id: bundle}`` map, keeping only the ones that verify —
    the input to ``signed_alias_for``."""
    out: dict[str, SelfDescription] = {}
    for canonical_id, bundle in bundles.items():
        sd = verify_self_description(bundle, now=now)
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
