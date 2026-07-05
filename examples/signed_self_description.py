"""Catch the agent's own key equivocating on its self-description.

The agent signs a self-description (aliases + endpoints), bumping ``seq`` on each
re-issue. Here two sources serve descriptions at the SAME ``seq`` with DIFFERENT
content, both signed by the agent's key — only a compromised or lying key could
produce that, so reconciling across sources reports ``agent_equivocation`` and
correspondence fails closed (no canonical).

Needs the ``attestation`` extra (Ed25519 / did:key / JCS).

Run:  python examples/signed_self_description.py
"""

from __future__ import annotations

import asyncio

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from sm_divergence import HttpDescriptionResolver, build_self_description, corroborate_descriptions

SERVICES = {"discovery": "https://acme.example/agents/acme"}


def raw_private() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def serves(bundle: dict) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(200, json=bundle))


async def main() -> None:
    key = raw_private()  # the agent's did:key private key
    real = build_self_description({"web": "did:web:acme.org"}, SERVICES, key, seq=5)
    forged = build_self_description({"web": "did:web:attacker.example"}, SERVICES, key, seq=5)

    resolvers = [
        HttpDescriptionResolver("https://a.example", transport=serves(real), label="src-a"),
        HttpDescriptionResolver("https://b.example", transport=serves(forged), label="src-b"),
    ]
    rec = (await corroborate_descriptions(resolvers, ["acme"]))["acme"]

    print("findings:  ", [(f.kind, f.detail) for f in rec.findings])
    print("canonical: ", rec.canonical, "  (None → correspondence fails closed)")


if __name__ == "__main__":
    asyncio.run(main())
