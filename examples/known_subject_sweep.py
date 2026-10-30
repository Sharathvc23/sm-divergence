"""Corroborate Resolution Registries about a Known Subject — the one-hop,
DAWN-aligned shape (``known-subject-resolution-02``).

Three registries each expose ``POST /resolve`` and are asked the same question
about ``orders@moon-bakery.example``. The sweep tells three conditions apart that
a plain endpoint comparison would collapse into one "divergence":

- registry **b** is one lease sequence behind **a**: ``stale_binding``, attributed
  to b, and b's superseded target is *not* compared against a's — lag is not
  tampering;
- registry **c** is current and agrees with a on the address but serves a
  different ``targetDigest``: ``digest`` — the same host is serving two documents,
  which is substitution at the host, not at the registry;
- a fourth registry **d** validates the subject through a different issuer at an
  unrelated sequence: no finding at all, because sequences only count within one
  authority scope and the issuer is provenance, not a compared field.

Network-free, via an injected httpx transport per registry.

Run:  python examples/known_subject_sweep.py
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sm_resolver import Corroborator

from sm_divergence.discovery import KnownSubjectResolver

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
SUBJECT = "orders@moon-bakery.example"


def _ts(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def target(*, url: str, digest: str, sequence: int, issuer: str) -> dict[str, Any]:
    return {
        "subject": SUBJECT,
        "subjectType": "agent-name",
        "method": "artifact",
        "targetType": "application/a2a-agent-card+json",
        "targetUrl": url,
        "targetDigest": digest,
        "sequence": sequence,
        "issuedAt": _ts(NOW - timedelta(hours=1)),
        "expiresAt": _ts(NOW + timedelta(days=1)),
        "authority": {"type": "domain-control", "issuer": issuer},
    }


def registry(registry_id: str, targets: list[dict[str, Any]]) -> httpx.MockTransport:
    """A Resolution Registry that answers POST /resolve with ``targets``."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST" and request.url.path == "/resolve"
        return httpx.Response(
            200,
            json={
                "registry": {"id": registry_id, "profile": "known-subject-resolution-02", "issuedAt": _ts(NOW)},
                "subject": SUBJECT,
                "subjectType": "agent-name",
                "targets": targets,
            },
        )

    return httpx.MockTransport(handler)


def resolver(name: str, targets: list[dict[str, Any]]) -> KnownSubjectResolver:
    rid = f"https://{name}.example"
    return KnownSubjectResolver(rid, transport=registry(rid, targets), label=name, now=lambda: NOW)


async def main() -> None:
    issuer = "https://issuer.example"
    card = "https://cards.agenthost.example/moon-bakery/orders.json"

    sources = [
        resolver("a", [target(url=card, digest="sha256:CURRENT", sequence=14, issuer=issuer)]),
        resolver(
            "b", [target(url="https://old-host.example/orders.json", digest="sha256:OLD", sequence=13, issuer=issuer)]
        ),
        resolver("c", [target(url=card, digest="sha256:TAMPERED", sequence=14, issuer=issuer)]),
        resolver("d", [target(url=card, digest="sha256:CURRENT", sequence=2, issuer="https://other-issuer.example")]),
    ]

    (result,) = await Corroborator(sources).check([SUBJECT])
    print(f"{result.agent_id}: {result.verdict}")
    for claim in result.claims:
        view = claim.view.comparable() if claim.view is not None else None
        binding = claim.view.binding() if claim.view is not None else None
        pos = f" seq={binding.sequence} scope={binding.scope}" if binding else ""
        print(f"  claim   [{claim.source}] status={claim.status}{pos} view={view}")
    for f in result.findings:
        print(f"  finding {f.kind:14} {f.confirmation}  {f.detail}")

    kinds = sorted(f.kind for f in result.findings)
    assert kinds == ["digest", "stale_binding"], kinds
    stale = next(f for f in result.findings if f.kind == "stale_binding")
    assert stale.detail["source"] == "b"
    digest = next(f for f in result.findings if f.kind == "digest")
    assert set(digest.detail["values"]) == {"a", "c", "d"}, digest.detail
    print(
        "\nOK: b attributed as stale (not accused of tampering); c's digest substitution caught; d's unrelated scope ignored."
    )


if __name__ == "__main__":
    asyncio.run(main())
