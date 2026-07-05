"""A hijacked did:web serves a different key than the agent's did:key root.

The ``did:key`` is resolved offline — it *is* the key, the self-certifying root
of truth. The ``did:web`` is fetched (here from an injected transport) and serves
a DIFFERENT verification key, so corroborating the two methods yields a ``key``
divergence: the identity-layer analogue of endpoint tampering (a hijacked domain,
a stale mirror, a lying resolver).

Run:  python examples/identity_key_divergence.py
"""

from __future__ import annotations

import asyncio

import httpx

from sm_divergence import Corroborator, DidKeyResolver, DidWebResolver

ROOT_KEY = "z6MkROOTkeyExampleAAAA"
IMPOSTER_KEY = "z6MkIMPOSTERkeyExampleB"


def serves_key(multibase: str) -> httpx.MockTransport:
    doc = {"verificationMethod": [{"type": "Ed25519VerificationKey2020", "publicKeyMultibase": multibase}]}
    return httpx.MockTransport(lambda request: httpx.Response(200, json=doc))


async def main() -> None:
    did_key = DidKeyResolver(did_for=lambda a: f"did:key:{ROOT_KEY}", label="did:key")
    did_web = DidWebResolver(
        did_for=lambda a: "did:web:acme.example", transport=serves_key(IMPOSTER_KEY), label="did:web"
    )
    for r in await Corroborator([did_key, did_web]).check(["acme"]):
        print(f"  {r.agent_id}: {r.verdict}")
        for f in r.findings:
            print(f"    [{f.kind}/{f.confirmation}] {f.detail}")


if __name__ == "__main__":
    asyncio.run(main())
