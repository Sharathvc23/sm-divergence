"""ANS resolver — the one-hop GET /ans/agents/{id}, and every claim-state edge."""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from sm_divergence.discovery.ans_v2 import AnsV2Resolver
from sm_divergence.discovery.views import RecordView

ANS = "https://ans.example"


def _resolver(handler: Any, **kw: Any) -> AnsV2Resolver:
    return AnsV2Resolver(ANS, transport=httpx.MockTransport(handler), **kw)


def _one_hop(record: httpx.Response) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.startswith("/ans/agents/"), f"unexpected path {request.url.path}"
        return record

    return handler


@pytest.mark.asyncio
async def test_resolve_success() -> None:
    status, view = await _resolver(_one_hop(httpx.Response(200, json={"endpoint": "https://agent.example/"}))).resolve(
        "payments-bot"
    )
    assert status == "present"
    assert view is not None and view.endpoint == "https://agent.example"


@pytest.mark.asyncio
async def test_404_is_no_claim_by_default() -> None:
    # On a route that answers 404 for a record the caller may not see, "not
    # found" is not a claim of absence. The default never turns it into one.
    assert await _resolver(_one_hop(httpx.Response(404))).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_404_is_absent_where_the_route_says_it_means_that() -> None:
    resolver = _resolver(_one_hop(httpx.Response(404)), not_found_is_absent=True)
    assert await resolver.resolve("x") == ("absent", None)


@pytest.mark.asyncio
async def test_soft_404_follows_the_same_switch() -> None:
    handler = _one_hop(httpx.Response(200, json={"success": False, "error": "agent not found"}))
    assert await _resolver(handler).resolve("x") == ("error", None)
    assert await _resolver(handler, not_found_is_absent=True).resolve("x") == ("absent", None)


@pytest.mark.asyncio
async def test_default_adapter_reads_the_endpoints_list() -> None:
    record = {
        "endpoints": [
            {
                "protocol": "A2A",
                "agentUrl": "https://agent.example/a2a",
                "metaDataUrl": "https://agent.example/card.json",
            },
            {"protocol": "MCP", "agentUrl": "https://agent.example/mcp"},
        ]
    }
    handler = _one_hop(httpx.Response(200, json=record))
    _, view = await _resolver(handler, protocol="a2a").resolve("x")
    assert view is not None and view.endpoint == "https://agent.example/card.json"
    _, service = await _resolver(handler, protocol="mcp", target="service").resolve("x")
    assert service is not None and service.endpoint == "https://agent.example/mcp"
    # Several protocols registered and none chosen: the entries disagree, so no claim.
    assert await _resolver(handler).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_name_mapping_that_fails_is_not_raised() -> None:
    def boom(agent_id: str) -> str:
        raise KeyError(agent_id)

    assert await _resolver(_one_hop(httpx.Response(200, json={})), ansname_for=boom).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_non_200_is_error() -> None:
    assert await _resolver(_one_hop(httpx.Response(500))).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_non_dict_body_is_error() -> None:
    assert await _resolver(_one_hop(httpx.Response(200, json=["not", "a", "dict"]))).resolve("x") == (
        "error",
        None,
    )


@pytest.mark.asyncio
async def test_ansname_for_maps_the_canonical_id() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        return httpx.Response(200, json={"endpoint": "https://agent.example"})

    resolver = _resolver(handler, ansname_for=lambda aid: f"acme.{aid}")
    await resolver.resolve("alice")
    assert seen["path"] == "/ans/agents/acme.alice"


@pytest.mark.asyncio
async def test_uses_custom_record_path() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"endpoint": "https://agent.example"})

    await _resolver(handler, record_path="/v2/agents/{id}.json").resolve("x")
    assert seen["url"] == "https://ans.example/v2/agents/x.json"


@pytest.mark.asyncio
async def test_default_adapter_contributes_no_did() -> None:
    # endpoint/omission divergence need no crypto; an unverified ANS record
    # contributes endpoint only — no did until a cert-verifying adapter is supplied.
    _, view = await _resolver(
        _one_hop(httpx.Response(200, json={"endpoint": "https://agent.example", "did": "did:key:zSpoofed"}))
    ).resolve("x")
    assert view is not None and view.did is None


@pytest.mark.asyncio
async def test_injected_adapter_can_contribute_a_did() -> None:
    # The ANS-2/ANS-4 verification lives in the adapter (downstream); the resolver
    # just carries whatever RecordView it returns.
    def verifying_adapter(doc: dict[str, Any]) -> RecordView:
        return RecordView(endpoint=str(doc.get("endpoint")).rstrip("/"), did="did:key:zVerified")

    _, view = await _resolver(
        _one_hop(httpx.Response(200, json={"endpoint": "https://agent.example/"})),
        adapter=verifying_adapter,
    ).resolve("x")
    assert view is not None and view.did == "did:key:zVerified"


def test_label_defaults_to_ans_url_and_is_overridable() -> None:
    assert AnsV2Resolver("https://ans.example/").label == "https://ans.example"
    assert AnsV2Resolver("https://ans.example", label="godaddy-ans").label == "godaddy-ans"


def test_vantage_is_exposed_for_split_horizon_detection() -> None:
    # Two instances, same label + different vantage → the Corroborator attributes
    # a disagreement to source_equivocation (split-horizon), not cross-source.
    r = AnsV2Resolver("https://ans.example", label="godaddy-ans", vantage="us-east")
    assert r.label == "godaddy-ans"
    assert r.vantage == "us-east"
