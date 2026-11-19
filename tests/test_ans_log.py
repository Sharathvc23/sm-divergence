"""AnsLogResolver — a transparency log's public badge as a discovery source.

The badge is the latest sealed event for one agent, and it attests the DNS
records the agent's zone held when it was sealed. The resolver reduces those
records by the rules the DNS resolvers apply to a live zone, so the log and the
zone are read alike.

The negative cases carry the weight: a revoked or expired registration is not a
claim of absence; a badge row naming another log is not this log's claim; an
entry about another host is not this subject's record; and a name with no badge
row means the log was never asked.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from _sweep import all_findings, kinds
from sm_resolver import (
    OUTCOME_REFUSED,
    OUTCOME_TIMEOUT,
    OUTCOME_UNPARSEABLE,
    OUTCOME_UNREACHABLE,
    OUTCOME_UNVERIFIABLE,
    Corroborator,
    Status,
)

from sm_divergence.discovery import (
    DIGEST,
    ENDPOINT,
    OUTCOME_AMBIGUOUS_RRSET,
    OUTCOME_EXPIRED,
    OUTCOME_NO_BADGE,
    OUTCOME_REVOKED,
    AnsLogResolver,
    AnsV2Resolver,
    DnsAnswer,
    DnsSvcbResolver,
    RecordView,
    ans_agent_adapter,
    default_adapter,
    split_badge_url,
    svcb_rows_from_text,
)

LOG = "https://log.example"
AGENT_ID = "3f0c1a52-6b0e-4d57-9a44-2f6f0d1e7c11"
FQDN = "agent.example.com"
CARD = "https://agent.example.com/.well-known/agent-card.json"
D_B64 = "9s_HMOu6_nLBerzY8AS1gJcOWqy_67fWyIMoKtfwqPU"
D_HEX = "f6cfc730ebbafe72c17abcd8f004b580970e5aacbfebb7d6c883282ad7f0a8f5"
D_CANON = "sha256:" + D_HEX

SVCB_A2A = f'1 . alpn="a2a" port=443 key65400="{CARD}" key65401="{D_B64}" key65402="a2a" key65409="agent-card.json"'
SVCB_MCP = '2 . alpn="mcp" port=443 key65400="https://agent.example.com/mcp.json" key65402="mcp"'
TXT_A2A = "v=ans1; version=v1; p=a2a; mode=direct; url=https://agent.example.com/a2a"
BADGE_TXT = f"v=ans-badge1; version=v1; url={LOG}/v1/agents/{AGENT_ID}"


def record(name: str, rdtype: str, data: str) -> dict[str, Any]:
    return {"name": name, "type": rdtype, "data": data}


def badge(
    *,
    status: str = "ACTIVE",
    host: str = FQDN,
    records: list[dict[str, Any]] | None = None,
    metadata_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    attestations: dict[str, Any] = {"domainValidation": "ACME-DNS-01"}
    if records is None:
        records = [record(FQDN, "SVCB", SVCB_A2A)]
    if records:
        attestations["dnsRecordsProvisioned"] = records
    if metadata_hashes is not None:
        attestations["metadataHashes"] = metadata_hashes
    return {
        "schemaVersion": "V2",
        "status": status,
        "signature": "detached..jws",
        "merkleProof": {"leafIndex": 4, "treeSize": 9, "leafHash": "00", "rootHash": "AA==", "path": []},
        "payload": {
            "logId": "8a1d7c0e-33f4-4a6b-b6d6-5a2b6f0c9e21",
            "producer": {
                "keyId": "ra-key-1",
                "signature": "detached..jws",
                "event": {
                    "ansId": AGENT_ID,
                    "ansName": f"ans://v1.0.0.{host}",
                    "eventType": "AGENT_REGISTERED",
                    "raId": "ra-example",
                    "timestamp": "2026-11-01T00:00:00Z",
                    "agent": {"host": host, "name": "Agent", "version": "1.0.0"},
                    "attestations": attestations,
                },
            },
        },
    }


def serve(response: httpx.Response, seen: list[httpx.Request] | None = None) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        return response

    return httpx.MockTransport(handler)


def by_id(doc: Any = None, *, status_code: int = 200, **kw: Any) -> AnsLogResolver:
    """A resolver that is told the agentId, so no DNS is involved."""
    response = httpx.Response(status_code, json=doc if doc is not None else badge())
    kw.setdefault("agent_id_for", lambda agent_id: AGENT_ID)
    return AnsLogResolver(LOG, transport=serve(response), **kw)


def badge_zone(*values: str, rcode: Any = "NOERROR") -> Any:
    async def query(name: str, rdtype: str) -> DnsAnswer:
        assert (name, rdtype) == (f"_ans-badge.{FQDN}.", "TXT")
        return DnsAnswer(rcode=rcode, txt=values)

    return query


async def outcome_of(resolver: AnsLogResolver, agent_id: str = FQDN) -> tuple[Status, RecordView | None, str]:
    return await resolver.resolve_with_outcome(agent_id)


# --- the request --------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_is_the_public_badge_route() -> None:
    seen: list[httpx.Request] = []
    resolver = AnsLogResolver(
        LOG + "/", agent_id_for=lambda agent_id: AGENT_ID, transport=serve(httpx.Response(200, json=badge()), seen)
    )
    assert (await resolver.resolve(FQDN))[0] == "present"
    (request,) = seen
    assert request.method == "GET"
    assert str(request.url) == f"{LOG}/v1/agents/{AGENT_ID}"
    assert "authorization" not in request.headers


def test_label_defaults_to_the_log_url() -> None:
    assert by_id().label == LOG
    assert by_id(label="log-a", vantage="us").vantage == "us"


# --- what the badge contributes ----------------------------------------------


@pytest.mark.asyncio
async def test_attested_svcb_rows_are_read_like_a_live_zone() -> None:
    status, view, outcome = await outcome_of(by_id())
    assert (status, outcome) == ("present", "present")
    assert view is not None
    assert view.endpoint == CARD
    assert view.comparable()[DIGEST] == D_CANON
    assert view.did is None and view.binding() is None


@pytest.mark.asyncio
async def test_target_and_protocol_apply_to_the_attested_rows() -> None:
    doc = badge(records=[record(FQDN, "SVCB", SVCB_A2A), record(FQDN, "SVCB", SVCB_MCP)])
    _, service, _ = await outcome_of(by_id(doc, target="service"))
    assert service is not None and service.comparable()[ENDPOINT] == "https://agent.example.com/"
    _, mcp, _ = await outcome_of(by_id(doc, protocol="mcp"))
    assert mcp is not None and mcp.endpoint == "https://agent.example.com/mcp.json"
    assert (await outcome_of(by_id(doc, protocol="x-http")))[0] == "absent"


@pytest.mark.asyncio
async def test_records_for_other_names_are_not_this_agents() -> None:
    doc = badge(
        records=[
            record("other.example.com", "SVCB", SVCB_MCP),
            record(FQDN + ".", "svcb", SVCB_A2A),  # trailing dot and case are the same name and type
            record(f"_443._tcp.{FQDN}", "TLSA", "3 0 1 abcdef"),
        ]
    )
    _, view, _ = await outcome_of(by_id(doc))
    assert view is not None and view.endpoint == CARD


@pytest.mark.parametrize(
    "data", [TXT_A2A, f'"{TXT_A2A}"', '"v=ans1; version=v1; p=a2a; mode=direct; url=https://agent.exa" "mple.com/a2a"']
)
@pytest.mark.asyncio
async def test_attested_txt_rows_are_read_when_no_svcb_is_attested(data: str) -> None:
    doc = badge(records=[record(f"_ans.{FQDN}", "TXT", data), record(f"_ans-badge.{FQDN}", "TXT", BADGE_TXT)])
    status, view, _ = await outcome_of(by_id(doc))
    assert status == "present"
    assert view == RecordView(endpoint="https://agent.example.com/a2a")


@pytest.mark.asyncio
async def test_live_registration_attesting_no_discovery_record_has_nothing_to_compare() -> None:
    status, view, _ = await outcome_of(by_id(badge(records=[])))
    assert (status, view) == ("present", RecordView())


@pytest.mark.asyncio
async def test_metadata_hash_fills_a_digest_the_rows_do_not_carry() -> None:
    row = f'1 . alpn="a2a" key65400="{CARD}" key65402="a2a"'
    doc = badge(records=[record(FQDN, "SVCB", row)], metadata_hashes={"A2A": "SHA256:" + D_HEX})
    _, view, _ = await outcome_of(by_id(doc, protocol="a2a"))
    assert view is not None and view.comparable()[DIGEST] == D_CANON
    # With one hash attested and no protocol configured, it is unambiguous.
    _, single, _ = await outcome_of(by_id(doc))
    assert single is not None and single.comparable()[DIGEST] == D_CANON
    # A hash for another protocol is not this row's.
    other = badge(records=[record(FQDN, "SVCB", row)], metadata_hashes={"MCP": "SHA256:" + "0" * 64})
    _, unpinned, _ = await outcome_of(by_id(other, protocol="a2a"))
    assert unpinned is not None and unpinned.digest is None


@pytest.mark.asyncio
async def test_two_attested_hashes_without_a_protocol_fill_nothing() -> None:
    row = f'1 . alpn="a2a" key65400="{CARD}"'
    doc = badge(
        records=[record(FQDN, "SVCB", row)],
        metadata_hashes={"A2A": "SHA256:" + D_HEX, "MCP": "SHA256:" + "0" * 64},
    )
    _, view, _ = await outcome_of(by_id(doc))
    assert view is not None and view.digest is None


@pytest.mark.asyncio
async def test_published_digest_is_not_overridden_by_the_metadata_hash() -> None:
    doc = badge(metadata_hashes={"A2A": "SHA256:" + "0" * 64})
    _, view, _ = await outcome_of(by_id(doc))
    assert view is not None and view.comparable()[DIGEST] == D_CANON


# --- status -------------------------------------------------------------------


@pytest.mark.parametrize("status", ["ACTIVE", "WARNING", "DEPRECATED"])
@pytest.mark.asyncio
async def test_live_statuses_are_present(status: str) -> None:
    assert (await outcome_of(by_id(badge(status=status))))[0] == "present"


@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        ("REVOKED", OUTCOME_REVOKED),
        ("EXPIRED", OUTCOME_EXPIRED),
        ("VERIFIED", OUTCOME_UNPARSEABLE),
        ("", OUTCOME_UNPARSEABLE),
    ],
)
@pytest.mark.asyncio
async def test_a_registration_that_is_not_live_is_not_a_claim_of_absence(status: str, outcome: str) -> None:
    assert await outcome_of(by_id(badge(status=status))) == ("error", None, outcome)


# --- response classification --------------------------------------------------


@pytest.mark.asyncio
async def test_404_on_the_public_route_is_absent() -> None:
    assert await outcome_of(by_id(status_code=404)) == ("absent", None, "absent")


@pytest.mark.parametrize(
    ("code", "outcome"),
    [(401, OUTCOME_REFUSED), (403, OUTCOME_REFUSED), (500, OUTCOME_UNREACHABLE), (503, OUTCOME_UNREACHABLE)],
)
@pytest.mark.asyncio
async def test_other_statuses_are_not_claims(code: int, outcome: str) -> None:
    assert await outcome_of(by_id(status_code=code)) == ("error", None, outcome)


@pytest.mark.asyncio
async def test_timeout_and_transport_failure() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    for handler, outcome in ((timeout, OUTCOME_TIMEOUT), (broken, OUTCOME_UNREACHABLE)):
        resolver = AnsLogResolver(LOG, agent_id_for=lambda a: AGENT_ID, transport=httpx.MockTransport(handler))
        assert await outcome_of(resolver) == ("error", None, outcome)


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        json.dumps(["a", "list"]).encode(),
        json.dumps({"status": "ACTIVE"}).encode(),  # no payload
        json.dumps({"status": "ACTIVE", "payload": {"producer": {"event": {"agent": {}}}}}).encode(),
        json.dumps(badge(host="not a host")).encode(),
        json.dumps(badge(records=[record(FQDN, "SVCB", '1 . alpn="a2a" proto=a2a')])).encode(),
        json.dumps(badge(records=[{"name": FQDN}])).encode(),
    ],
)
@pytest.mark.asyncio
async def test_a_badge_that_cannot_be_read_is_unparseable(body: bytes) -> None:
    resolver = AnsLogResolver(LOG, agent_id_for=lambda a: AGENT_ID, transport=serve(httpx.Response(200, content=body)))
    assert await outcome_of(resolver) == ("error", None, OUTCOME_UNPARSEABLE)


@pytest.mark.asyncio
async def test_attested_rows_that_disagree_are_ambiguous() -> None:
    doc = badge(
        records=[
            record(FQDN, "SVCB", '1 . alpn="a2a" key65400="https://a.example/1.json"'),
            record(FQDN, "SVCB", '1 . alpn="a2a" key65400="https://a.example/2.json"'),
        ]
    )
    assert await outcome_of(by_id(doc)) == ("error", None, OUTCOME_AMBIGUOUS_RRSET)


# --- the subject must match ---------------------------------------------------


@pytest.mark.asyncio
async def test_an_entry_about_another_host_is_not_this_subjects_record() -> None:
    resolver = by_id(badge(host="other.example.com", records=[]), owner_for=lambda agent_id: FQDN)
    assert await outcome_of(resolver) == ("error", None, OUTCOME_UNVERIFIABLE)


@pytest.mark.asyncio
async def test_without_owner_for_the_mapped_entry_is_taken_as_given() -> None:
    resolver = by_id(badge(host="other.example.com", records=[]))
    assert (await outcome_of(resolver, "watch-id-7"))[0] == "present"


@pytest.mark.asyncio
async def test_agent_id_mapping_that_fails_or_is_not_an_id_sends_no_request() -> None:
    seen: list[httpx.Request] = []

    def boom(agent_id: str) -> str:
        raise KeyError(agent_id)

    for mapping in (boom, lambda a: "", lambda a: "a/b"):
        resolver = AnsLogResolver(LOG, agent_id_for=mapping, transport=serve(httpx.Response(200, json=badge()), seen))
        assert await outcome_of(resolver) == ("error", None, OUTCOME_UNPARSEABLE)
    assert seen == []


# --- locating the entry through the badge row ---------------------------------


def located(*values: str, doc: Any = None, seen: list[httpx.Request] | None = None, **kw: Any) -> AnsLogResolver:
    response = httpx.Response(200, json=doc if doc is not None else badge())
    return AnsLogResolver(LOG, badge_query=badge_zone(*values), transport=serve(response, seen), **kw)


@pytest.mark.asyncio
async def test_badge_row_names_the_entry_to_ask_for() -> None:
    seen: list[httpx.Request] = []
    resolver = located(BADGE_TXT, "v=spf1 -all", seen=seen)
    status, view, _ = await outcome_of(resolver)
    assert status == "present" and view is not None and view.endpoint == CARD
    assert str(seen[0].url) == f"{LOG}/v1/agents/{AGENT_ID}"


@pytest.mark.asyncio
async def test_badge_row_naming_another_log_is_not_this_logs_claim() -> None:
    seen: list[httpx.Request] = []
    resolver = located(f"v=ans-badge1; version=v1; url=https://other-log.example/v1/agents/{AGENT_ID}", seen=seen)
    assert await outcome_of(resolver) == ("error", None, OUTCOME_UNVERIFIABLE)
    assert seen == []


@pytest.mark.asyncio
async def test_log_url_is_compared_as_an_address_not_a_string() -> None:
    resolver = located(f"v=ANS-BADGE1; url=HTTPS://LOG.example:443/v1/agents/{AGENT_ID}/")
    assert (await outcome_of(resolver))[0] == "present"


@pytest.mark.asyncio
async def test_no_badge_row_means_the_log_was_never_asked() -> None:
    seen: list[httpx.Request] = []
    for resolver in (
        located("v=spf1 -all", seen=seen),
        located(seen=seen),
        AnsLogResolver(LOG, badge_query=badge_zone(rcode="NXDOMAIN"), transport=serve(httpx.Response(404), seen)),
    ):
        assert await outcome_of(resolver) == ("error", None, OUTCOME_NO_BADGE)
    assert seen == []


@pytest.mark.asyncio
async def test_badge_lookup_failures_keep_their_outcome() -> None:
    for rcode, outcome in (("SERVFAIL", OUTCOME_UNREACHABLE), ("REFUSED", OUTCOME_REFUSED)):
        resolver = AnsLogResolver(LOG, badge_query=badge_zone(rcode=rcode), transport=serve(httpx.Response(404)))
        assert await outcome_of(resolver) == ("error", None, outcome)


@pytest.mark.asyncio
async def test_two_badge_rows_naming_different_entries_are_ambiguous() -> None:
    other = f"v=ans-badge1; url={LOG}/v1/agents/00000000-0000-4000-8000-000000000000"
    assert await outcome_of(located(BADGE_TXT, other)) == ("error", None, OUTCOME_AMBIGUOUS_RRSET)
    # The same entry named twice is one entry.
    assert (await outcome_of(located(BADGE_TXT, BADGE_TXT)))[0] == "present"


@pytest.mark.asyncio
async def test_badge_row_without_a_usable_url_is_unparseable() -> None:
    for value in ("v=ans-badge1; version=v1", "v=ans-badge1; url=https://log.example/elsewhere"):
        assert await outcome_of(located(value)) == ("error", None, OUTCOME_UNPARSEABLE)


@pytest.mark.asyncio
async def test_located_entry_must_be_about_the_name_it_was_located_from() -> None:
    resolver = located(BADGE_TXT, doc=badge(host="other.example.com", records=[]))
    assert await outcome_of(resolver) == ("error", None, OUTCOME_UNVERIFIABLE)


@pytest.mark.asyncio
async def test_an_id_that_is_not_a_dns_name_cannot_be_located() -> None:
    assert await outcome_of(located(BADGE_TXT), "agent-1") == ("error", None, OUTCOME_UNPARSEABLE)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (f"{LOG}/v1/agents/{AGENT_ID}", (LOG, AGENT_ID)),
        (f"  {LOG}/prefix/v1/agents/{AGENT_ID}/ ", (LOG + "/prefix", AGENT_ID)),
        (f"{LOG}/v1/agents/", None),
        (f"{LOG}/v1/agents/{AGENT_ID}/audit", None),
        ("ftp://log.example/v1/agents/x", None),
        ("", None),
    ],
)
def test_split_badge_url(url: str, expected: tuple[str, str] | None) -> None:
    assert split_badge_url(url) == expected


# --- sweep-level: a log beside the zone it attests ----------------------------


def zone(*records: str) -> DnsSvcbResolver:
    async def query(name: str, rdtype: str) -> DnsAnswer:
        return DnsAnswer(svcb=svcb_rows_from_text(*records)) if name == FQDN + "." else DnsAnswer(rcode="NXDOMAIN")

    return DnsSvcbResolver(query=query)


@pytest.mark.asyncio
async def test_log_and_zone_holding_the_same_records_agree() -> None:
    results = await Corroborator([by_id(label="log"), zone(SVCB_A2A)]).check([FQDN])
    assert all_findings(results) == []
    assert results[0].verdict == "AGREE"


@pytest.mark.asyncio
async def test_zone_changed_after_sealing_diverges_from_the_log() -> None:
    moved = f'1 . alpn="a2a" key65400="https://elsewhere.example/card.json" key65401="{D_B64}" key65402="a2a"'
    results = await Corroborator([by_id(label="log"), zone(moved)]).check([FQDN])
    assert kinds(results) == [ENDPOINT]


@pytest.mark.asyncio
async def test_same_address_serving_another_document_is_a_digest_finding() -> None:
    swapped = f'1 . alpn="a2a" key65400="{CARD}" key65401="{"A" * 43}" key65402="a2a"'
    results = await Corroborator([by_id(label="log"), zone(swapped)]).check([FQDN])
    assert kinds(results) == [DIGEST]


@pytest.mark.asyncio
async def test_revoked_registration_is_excluded_not_counted_as_an_omission() -> None:
    results = await Corroborator([by_id(badge(status="REVOKED"), label="log"), zone(SVCB_A2A)]).check([FQDN])
    assert all_findings(results) == []
    outcomes = {claim.source: claim.outcome for claim in results[0].claims}
    assert outcomes["log"] == OUTCOME_REVOKED


# --- the by-id resolver: a 404 that is not a claim ----------------------------

ANS = "https://ans.example"


def ans(response: httpx.Response, **kw: Any) -> AnsV2Resolver:
    return AnsV2Resolver(ANS, transport=serve(response), **kw)


@pytest.mark.asyncio
async def test_by_id_404_is_no_claim_unless_the_route_says_otherwise() -> None:
    assert await ans(httpx.Response(404)).resolve("x") == ("error", None)
    assert await ans(httpx.Response(404), not_found_is_absent=True).resolve("x") == ("absent", None)


@pytest.mark.asyncio
async def test_a_404_that_is_no_claim_is_not_an_omission() -> None:
    hidden = ans(httpx.Response(404), label="ans")
    results = await Corroborator([hidden, zone(SVCB_A2A)]).check([FQDN])
    assert all_findings(results) == []


RECORD = {
    "agentId": AGENT_ID,
    "agentHost": FQDN,
    "endpoints": [
        {
            "protocol": "A2A",
            "agentUrl": "https://agent.example.com/a2a",
            "metaDataUrl": CARD,
            "metaDataHash": "SHA256:" + D_HEX,
        },
        {"protocol": "MCP", "agentUrl": "https://agent.example.com/mcp"},
    ],
}


@pytest.mark.asyncio
async def test_endpoints_list_is_read_by_the_agent_adapter() -> None:
    response = httpx.Response(200, json=RECORD)
    _, view = await ans(response, adapter=ans_agent_adapter(protocol="a2a")).resolve("x")
    assert view is not None and view.endpoint == CARD and view.comparable()[DIGEST] == D_CANON
    _, service = await ans(response, adapter=ans_agent_adapter(protocol="A2A", target="service")).resolve("x")
    assert service is not None and service.endpoint == "https://agent.example.com/a2a"
    # An entry with no descriptor contributes no endpoint, never the service address.
    _, mcp = await ans(response, adapter=ans_agent_adapter(protocol="mcp")).resolve("x")
    assert mcp == RecordView()
    _, mcp_service = await ans(response, adapter=ans_agent_adapter(protocol="mcp", target="service")).resolve("x")
    assert mcp_service is not None and mcp_service.endpoint == "https://agent.example.com/mcp"


@pytest.mark.asyncio
async def test_agent_adapter_edge_cases() -> None:
    # Several protocols and none chosen: the entries disagree, so no claim.
    assert await ans(httpx.Response(200, json=RECORD), adapter=ans_agent_adapter()).resolve("x") == ("error", None)
    # No entry for the protocol: the agent is registered, with nothing to compare.
    assert await ans(httpx.Response(200, json=RECORD), adapter=ans_agent_adapter(protocol="x-http")).resolve("x") == (
        "present",
        RecordView(),
    )
    # A record without endpoints[] falls back to a top-level endpoint.
    flat = httpx.Response(200, json={"endpoint": "https://agent.example/"})
    _, view = await ans(flat, adapter=ans_agent_adapter()).resolve("x")
    assert view is not None and view.endpoint == "https://agent.example"
    # The resolver's default adapter is this one: protocol and target pass through.
    _, default = await ans(httpx.Response(200, json=RECORD), protocol="a2a").resolve("x")
    assert default is not None and default.endpoint == CARD
    # The generic top-level adapter still reads no endpoints[] list.
    generic = ans(httpx.Response(200, json=RECORD), adapter=default_adapter)
    assert await generic.resolve("x") == ("present", RecordView())
    bad = httpx.Response(200, json={"endpoints": ["not-an-object"]})
    assert await ans(bad, adapter=ans_agent_adapter()).resolve("x") == ("error", None)


@pytest.mark.asyncio
async def test_registry_record_and_zone_compare_through_the_agent_adapter() -> None:
    registry = ans(httpx.Response(200, json=RECORD), adapter=ans_agent_adapter(protocol="a2a"), label="ans")
    results = await Corroborator([registry, zone(SVCB_A2A)]).check([FQDN])
    assert all_findings(results) == []
