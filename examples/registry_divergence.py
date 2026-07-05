"""Corroborate registries about an agent — a tampered endpoint and an omission.

Three NEST-style registries are asked about the same agent: one serves the real
endpoint, one an attacker's, and one hides the agent entirely. The detector
reports exactly the endpoint disagreement and the omission — network-free, via an
injected httpx transport per registry.

Run:  python examples/registry_divergence.py
"""

from __future__ import annotations

import asyncio

import httpx

from sm_divergence import DivergenceDetector, HttpByIdResolver


def registry(record: dict | None) -> httpx.MockTransport:
    """A registry that serves ``record`` at /api/agents/{id}, or 404 if None."""

    def handler(request: httpx.Request) -> httpx.Response:
        if record is None:
            return httpx.Response(404)
        return httpx.Response(200, json=record)

    return httpx.MockTransport(handler)


async def main() -> None:
    real = {"agent_id": "acme", "endpoint": "https://acme.example"}
    fake = {"agent_id": "acme", "endpoint": "https://attacker.example"}

    detector = DivergenceDetector(
        [
            HttpByIdResolver("https://reg-a.example", transport=registry(real), label="reg-a"),
            HttpByIdResolver("https://reg-b.example", transport=registry(fake), label="reg-b"),
            HttpByIdResolver("https://reg-c.example", transport=registry(None), label="reg-c"),
        ]
    )
    for r in await detector.check(["acme"]):
        print(f"  {r.agent_id}: {r.verdict}")
        for f in r.findings:
            print(f"    [{f.kind}/{f.confirmation}] {f.detail}")


if __name__ == "__main__":
    asyncio.run(main())
