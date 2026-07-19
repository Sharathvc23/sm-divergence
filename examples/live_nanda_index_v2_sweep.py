"""Corroborate a live NANDA Index v2 against two independent registries.

Unlike the other examples (network-free, mocked transports), this one talks to
REAL running services from ~/nanda-testbed (see TESTBED_STATE.md):

  nanda-index-v2   http://localhost:3001   (hop 1 — resolves the URN locator)
  nanda-registry   http://localhost:3002   (hop 2 — what "acme-corp"'s
                                             registry_url points at)
  host39           http://localhost:3010   (an INDEPENDENT registry hosting
                                             its own separate claim about the
                                             same agent identity, unrelated to
                                             the Index's own pointer)

Three claims about the same watched id, from three genuinely independent
sources:
  1. via the Index's two-hop resolve (locator -> registry_url -> record)
  2. by hitting nanda-registry directly (bypassing the Index)
  3. by hitting host39 directly (a second registry that was never told about
     the Index's copy at all)

Sources (1) and (2) always agree by construction — they resolve to the same
backend. Source (3) is the one that can genuinely diverge, and did, in a real
run captured below: creating an agent in nanda-registry and an independent
card for the same identity in host39, both pointing at the same real URL,
then editing ONLY the host39 copy (bypassing both the Index and the
registry) reproduced a live DIVERGENT verdict:

    divergence-demo: DIVERGENT
     claim   nanda-index-v2 (via resolve)  present  endpoint=https://real.example/agent
     claim   nanda-registry (direct)       present  endpoint=https://real.example/agent
     claim   host39 (independent card)     present  endpoint=https://attacker.example/hijacked
     finding endpoint suspected {'field': 'endpoint', 'values': {
         'host39 (independent card)': 'https://attacker.example/hijacked',
         'nanda-index-v2 (via resolve)': 'https://real.example/agent',
         'nanda-registry (direct)': 'https://real.example/agent'}}

Restoring host39's copy re-swept back to AGREE. Full transcript in
examples/live_nanda_index_v2_sweep.OUTPUT.md (this script's setup steps
aren't reproduced here since they involve one-time registration calls against
each service — see that file for the exact curl commands used).

Both registries answer with a real ai-catalog-shaped record (field `url`, not
the NEST-default `endpoint`), so a custom adapter maps `url` -> `endpoint`.

Run (after seeding matching records on all three services — see the OUTPUT.md
transcript for the exact setup calls):
    python examples/live_nanda_index_v2_sweep.py
"""

from __future__ import annotations

import asyncio
from typing import Any

from sm_divergence import DivergenceDetector
from sm_divergence.discovery import HttpByIdResolver, RecordView
from sm_divergence.discovery.index_v2 import NandaIndexV2Resolver

INDEX_URL = "http://localhost:3001"
REGISTRY_URL = "http://localhost:3002"
HOST39_URL = "http://localhost:3010"
ORG_DOMAIN = "acme-corp.test"
HOST39_DOMAIN = "divergence-demo.test"
AGENT_ID = "divergence-demo"


def ai_catalog_adapter(record: dict[str, Any]) -> RecordView:
    """ai-catalog / A2A card records use `url`, not the NEST-default `endpoint`."""
    url = record.get("url")
    return RecordView(endpoint=str(url) if isinstance(url, str) and url else None)


def locator_for(agent_id: str) -> str:
    return f"urn:ai:domain:{ORG_DOMAIN}:agent:{agent_id}"


async def main() -> None:
    detector = DivergenceDetector(
        [
            NandaIndexV2Resolver(
                INDEX_URL,
                locator_for=locator_for,
                record_path="/agents/{id}",
                adapter=ai_catalog_adapter,
                label="nanda-index-v2 (via resolve)",
            ),
            HttpByIdResolver(
                REGISTRY_URL,
                path="/agents/{id}",
                adapter=ai_catalog_adapter,
                label="nanda-registry (direct)",
            ),
            HttpByIdResolver(
                HOST39_URL,
                path=f"/{HOST39_DOMAIN}/{{id}}.json",
                adapter=ai_catalog_adapter,
                label="host39 (independent card)",
            ),
        ]
    )

    print(f"registries: {detector.registries}")
    results = await detector.check([AGENT_ID])
    for r in results:
        print(f"\n{r.agent_id}: {r.verdict}")
        for c in r.claims:
            print(f"  claim  [{c.source}] status={c.status} view={c.view}")
        for f in r.findings:
            print(f"  finding [{f.kind}/{f.confirmation}] {f.detail}")


if __name__ == "__main__":
    asyncio.run(main())
