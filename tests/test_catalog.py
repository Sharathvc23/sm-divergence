"""CatalogResolver — a published AI Catalog document as a discovery source.

A catalog lists a publisher's artifacts; the entry whose identifier names a
subject says where its descriptor is and, optionally, what it hashes to.

The negative cases carry the weight: no catalog at all is not a claim of
absence; a listing delegated to a document that was not read cannot support
one; and several artifacts for one subject are not this adapter's to choose
between.
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
    Corroborator,
    Status,
)

from sm_divergence.discovery import (
    DIGEST,
    ENDPOINT,
    OUTCOME_AMBIGUOUS_ENTRY,
    OUTCOME_NESTED_NOT_READ,
    OUTCOME_NO_CATALOG,
    OUTCOME_REDIRECTED,
    CatalogResolver,
    DnsAnswer,
    DnsSvcbResolver,
    RecordView,
    air_identifier,
    entry_to_view,
    latest_entries,
    svcb_rows_from_text,
)

HOST = "https://agent.example.com"
WELL_KNOWN = HOST + "/.well-known/ai-catalog.json"
ID = "urn:air:agent.example.com:support"
CARD = "https://agent.example.com/.well-known/agent-card.json"
MCP_CARD = "https://agent.example.com/.well-known/mcp.json"
A2A = "application/a2a-agent-card+json"
MCP = "application/mcp-server-card+json"
CATALOG = "application/ai-catalog+json"
D_HEX = "f6cfc730ebbafe72c17abcd8f004b580970e5aacbfebb7d6c883282ad7f0a8f5"
D_B64 = "9s_HMOu6_nLBerzY8AS1gJcOWqy_67fWyIMoKtfwqPU"
DIGEST_VALUE = "sha256:" + D_HEX


def entry(identifier: str = ID, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {"identifier": identifier, "type": A2A, "url": CARD, "digest": DIGEST_VALUE}
    base.update(over)
    return {key: value for key, value in base.items() if value is not None}


def catalog(*entries: Any, **over: Any) -> dict[str, Any]:
    return {"specVersion": "0.9", "host": {"displayName": "Example"}, "entries": list(entries), **over}


def site(documents: dict[str, Any], seen: list[str] | None = None) -> httpx.MockTransport:
    """Serve ``url -> document`` (a dict/list, an ``httpx.Response``, or an exception class)."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if seen is not None:
            seen.append(url)
        doc = documents.get(url)
        if doc is None:
            return httpx.Response(404)
        if isinstance(doc, httpx.Response):
            return doc
        if isinstance(doc, type) and issubclass(doc, Exception):
            raise doc("failed", request=request)
        return httpx.Response(200, json=doc)

    return httpx.MockTransport(handler)


def resolver(doc: Any = None, **kw: Any) -> CatalogResolver:
    documents = kw.pop("documents", None) or {WELL_KNOWN: doc if doc is not None else catalog(entry())}
    return CatalogResolver(HOST, transport=site(documents, kw.pop("seen", None)), **kw)


async def outcome_of(r: CatalogResolver, agent_id: str = ID) -> tuple[Status, RecordView | None, str]:
    return await r.resolve_with_outcome(agent_id)


# --- the request --------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_is_one_get_of_the_well_known_document() -> None:
    seen: list[str] = []
    assert (await outcome_of(CatalogResolver(HOST + "/", transport=site({WELL_KNOWN: catalog(entry())}, seen))))[
        0
    ] == "present"
    assert seen == [WELL_KNOWN]


@pytest.mark.asyncio
async def test_catalog_paths_are_tried_in_order() -> None:
    seen: list[str] = []
    other = HOST + "/.well-known/other.json"
    r = resolver(
        documents={WELL_KNOWN: catalog(entry())},
        seen=seen,
        catalog_paths=["/.well-known/other.json", "/.well-known/ai-catalog.json"],
    )
    assert (await outcome_of(r))[0] == "present"
    assert seen == [other, WELL_KNOWN]


@pytest.mark.asyncio
async def test_a_catalog_may_be_named_by_its_own_url() -> None:
    url = "https://cdn.example/catalogs/acme.json"
    r = CatalogResolver(url, catalog_paths=("",), transport=site({url: catalog(entry())}))
    assert (await outcome_of(r))[0] == "present"


def test_label_and_vantage() -> None:
    assert resolver().label == HOST
    assert resolver(label="publisher", vantage="eu").vantage == "eu"


# --- what an entry contributes ------------------------------------------------


@pytest.mark.asyncio
async def test_url_and_digest_become_the_view() -> None:
    status, view, outcome = await outcome_of(resolver())
    assert (status, outcome) == ("present", "present")
    assert view == RecordView(endpoint=CARD, digest=DIGEST_VALUE)
    assert view is not None and view.did is None and view.binding() is None


@pytest.mark.asyncio
async def test_entry_without_a_digest_contributes_none() -> None:
    _, view, _ = await outcome_of(resolver(catalog(entry(digest=None))))
    assert view == RecordView(endpoint=CARD)


@pytest.mark.asyncio
async def test_inline_artifact_has_no_address() -> None:
    doc = catalog(entry(url=None, data={"name": "agent"}))
    _, view, _ = await outcome_of(resolver(doc))
    assert view == RecordView(endpoint=None, digest=DIGEST_VALUE)


@pytest.mark.asyncio
async def test_earlier_discriminator_name_is_read() -> None:
    doc = catalog({"identifier": ID, "mediaType": A2A, "url": CARD})
    assert (await outcome_of(resolver(doc, artifact_type=A2A)))[0] == "present"


@pytest.mark.asyncio
async def test_unknown_members_are_ignored() -> None:
    doc = catalog(entry(futureMember={"x": 1}, extensions={"y": 2}), futureTopLevel=True)
    assert (await outcome_of(resolver(doc)))[0] == "present"


@pytest.mark.parametrize(
    "bad",
    [
        {"identifier": ID, "type": A2A},  # neither url nor data
        {"identifier": ID, "type": A2A, "url": CARD, "data": {}},  # both
        {"identifier": ID, "type": A2A, "url": ""},
        {"identifier": ID, "type": A2A, "url": 7},
        {"identifier": ID, "type": A2A, "url": CARD, "digest": 7},
        {"identifier": ID, "url": CARD},  # no type
    ],
)
@pytest.mark.asyncio
async def test_malformed_matched_entry_is_unparseable(bad: dict[str, Any]) -> None:
    assert await outcome_of(resolver(catalog(bad))) == ("error", None, OUTCOME_UNPARSEABLE)


@pytest.mark.asyncio
async def test_malformed_entries_for_other_subjects_do_not_matter() -> None:
    doc = catalog("not-an-object", {"identifier": "urn:air:other.example:x", "type": A2A}, entry())
    assert (await outcome_of(resolver(doc)))[0] == "present"


def test_entry_to_view() -> None:
    assert entry_to_view(entry()) == RecordView(endpoint=CARD, digest=DIGEST_VALUE)
    with pytest.raises(ValueError):
        entry_to_view({"identifier": ID, "type": A2A})


# --- selection ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_identifier_is_compared_exactly() -> None:
    assert (await outcome_of(resolver(), ID.upper()))[0] == "absent"
    assert (await outcome_of(resolver(), ID + ":agent"))[0] == "absent"


@pytest.mark.asyncio
async def test_identifier_for_maps_the_watch_id() -> None:
    r = resolver(identifier_for=lambda agent_id: air_identifier("agent.example.com", agent_id))
    assert (await outcome_of(r, "support"))[0] == "present"
    assert air_identifier("acme.com", "support-assistant", "agent") == "urn:air:acme.com:support-assistant:agent"


@pytest.mark.asyncio
async def test_identifier_mapping_that_fails_sends_no_request() -> None:
    seen: list[str] = []

    def boom(agent_id: str) -> str:
        raise KeyError(agent_id)

    for mapping in (boom, lambda a: ""):
        r = resolver(seen=seen, identifier_for=mapping)
        assert await outcome_of(r) == ("error", None, OUTCOME_UNPARSEABLE)
    assert seen == []


MULTI = {
    "identifier": ID,
    "type": CATALOG,
    "data": {
        "specVersion": "0.9",
        "entries": [
            {"identifier": ID + ":a2a", "type": A2A, "url": CARD, "digest": DIGEST_VALUE},
            {"identifier": ID + ":mcp", "type": MCP, "url": MCP_CARD},
        ],
    },
}


@pytest.mark.asyncio
async def test_subject_offered_over_several_protocols_needs_an_artifact_type() -> None:
    assert await outcome_of(resolver(catalog(MULTI))) == ("error", None, OUTCOME_AMBIGUOUS_ENTRY)
    _, a2a, _ = await outcome_of(resolver(catalog(MULTI), artifact_type=A2A))
    assert a2a == RecordView(endpoint=CARD, digest=DIGEST_VALUE)
    _, mcp, _ = await outcome_of(resolver(catalog(MULTI), artifact_type=MCP))
    assert mcp == RecordView(endpoint=MCP_CARD)


@pytest.mark.asyncio
async def test_no_artifact_of_the_type_is_absent() -> None:
    assert await outcome_of(resolver(artifact_type=MCP)) == ("absent", None, "absent")
    assert await outcome_of(resolver(catalog(MULTI), artifact_type="application/agent-skills+json")) == (
        "absent",
        None,
        "absent",
    )


@pytest.mark.asyncio
async def test_two_entries_that_agree_are_one_claim() -> None:
    doc = catalog(entry(version="1.0.0"), entry(version="1.0.0", url=CARD + "#frag"))
    assert (await outcome_of(resolver(doc)))[0] == "present"


@pytest.mark.asyncio
async def test_latest_version_is_taken() -> None:
    old = entry(version="1.9.0", url="https://agent.example.com/old.json")
    new = entry(version="1.10.0", url="https://agent.example.com/new.json")
    _, view, _ = await outcome_of(resolver(catalog(new, old)))
    assert view is not None and view.endpoint == "https://agent.example.com/new.json"


@pytest.mark.asyncio
async def test_updated_at_orders_entries_without_a_semantic_version() -> None:
    old = entry(version="spring", updatedAt="2026-03-01T00:00:00Z", url="https://agent.example.com/old.json")
    new = entry(version="autumn", updatedAt="2026-09-01T00:00:00+00:00", url="https://agent.example.com/new.json")
    _, view, _ = await outcome_of(resolver(catalog(old, new)))
    assert view is not None and view.endpoint == "https://agent.example.com/new.json"


@pytest.mark.asyncio
async def test_versions_that_cannot_be_ordered_and_disagree_are_ambiguous() -> None:
    doc = catalog(
        entry(version="a", url="https://agent.example.com/1.json"),
        entry(version="b", url="https://agent.example.com/2.json"),
    )
    assert await outcome_of(resolver(doc)) == ("error", None, OUTCOME_AMBIGUOUS_ENTRY)


def test_latest_entries() -> None:
    a, b, c = {"version": "1.2.3"}, {"version": "1.10.0"}, {"version": "1.10.0", "x": 1}
    assert latest_entries([a, b, c]) == [b, c]
    assert latest_entries([a]) == [a]
    assert latest_entries([]) == []
    # One unparseable version and no timestamps: nothing can be ordered.
    mixed = [{"version": "1.0.0"}, {"version": "1.0.0-rc.1"}]
    assert latest_entries(mixed) == mixed
    # A timestamp without an offset cannot be ordered against one with.
    naive = [{"updatedAt": "2026-01-01T00:00:00"}, {"updatedAt": "2026-02-01T00:00:00Z"}]
    assert latest_entries(naive) == naive


# --- never a false absent -----------------------------------------------------


@pytest.mark.asyncio
async def test_a_catalog_read_in_full_that_lists_no_such_identifier_is_absent() -> None:
    doc = catalog(entry("urn:air:agent.example.com:other"))
    assert await outcome_of(resolver(doc)) == ("absent", None, "absent")
    assert await outcome_of(resolver(catalog())) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_no_catalog_is_not_a_claim_of_absence() -> None:
    assert await outcome_of(resolver(documents={"https://elsewhere.example/": {}})) == (
        "error",
        None,
        OUTCOME_NO_CATALOG,
    )


@pytest.mark.parametrize(
    ("served", "outcome"),
    [
        (httpx.Response(401), OUTCOME_REFUSED),
        (httpx.Response(403), OUTCOME_REFUSED),
        (httpx.Response(500), OUTCOME_UNREACHABLE),
        (httpx.ReadTimeout, OUTCOME_TIMEOUT),
        (httpx.ConnectError, OUTCOME_UNREACHABLE),
        (httpx.Response(200, content=b"<html>"), OUTCOME_UNPARSEABLE),
        (httpx.Response(200, json=["a", "list"]), OUTCOME_UNPARSEABLE),
        (httpx.Response(200, json={"entries": []}), OUTCOME_UNPARSEABLE),  # no specVersion
        (httpx.Response(200, json={"specVersion": "0.9"}), OUTCOME_UNPARSEABLE),  # no entries
        (httpx.Response(200, json={"specVersion": "0.9", "entries": {}}), OUTCOME_UNPARSEABLE),
    ],
)
@pytest.mark.asyncio
async def test_a_catalog_that_cannot_be_read_is_not_a_claim(served: Any, outcome: str) -> None:
    assert await outcome_of(resolver(documents={WELL_KNOWN: served})) == ("error", None, outcome)


@pytest.mark.asyncio
async def test_a_redirect_is_not_followed_unless_asked() -> None:
    www = "https://www.agent.example.com/.well-known/ai-catalog.json"
    documents = {WELL_KNOWN: httpx.Response(301, headers={"location": www}), www: catalog(entry())}
    assert await outcome_of(resolver(documents=documents)) == ("error", None, OUTCOME_REDIRECTED)
    seen: list[str] = []
    status, view, _ = await outcome_of(resolver(documents=documents, seen=seen, follow_redirects=True))
    assert status == "present" and view is not None and view.endpoint == CARD
    assert seen == [WELL_KNOWN, www]


@pytest.mark.asyncio
async def test_a_failing_first_path_is_not_skipped() -> None:
    documents = {HOST + "/a.json": httpx.Response(500), HOST + "/b.json": catalog(entry())}
    r = resolver(documents=documents, catalog_paths=["/a.json", "/b.json"])
    assert await outcome_of(r) == ("error", None, OUTCOME_UNREACHABLE)


# --- nested catalogs ----------------------------------------------------------

DEPT = "https://agent.example.com/catalogs/dept.json"
DEPT_ENTRY = {"identifier": "urn:air:agent.example.com:dept", "type": CATALOG, "url": "/catalogs/dept.json"}


@pytest.mark.asyncio
async def test_inline_nested_catalog_is_searched() -> None:
    doc = catalog({"identifier": "urn:air:agent.example.com:dept", "type": CATALOG, "data": catalog(entry())})
    _, view, _ = await outcome_of(resolver(doc))
    assert view is not None and view.endpoint == CARD


@pytest.mark.asyncio
async def test_nested_catalog_by_url_is_not_read_by_default_and_blocks_absence() -> None:
    seen: list[str] = []
    documents = {WELL_KNOWN: catalog(DEPT_ENTRY), DEPT: catalog(entry())}
    assert await outcome_of(resolver(documents=documents, seen=seen)) == ("error", None, OUTCOME_NESTED_NOT_READ)
    assert seen == [WELL_KNOWN]


@pytest.mark.asyncio
async def test_subject_found_in_the_root_is_unaffected_by_an_unread_nested_catalog() -> None:
    documents = {WELL_KNOWN: catalog(DEPT_ENTRY, entry())}
    assert (await outcome_of(resolver(documents=documents)))[0] == "present"


@pytest.mark.asyncio
async def test_follow_nested_reads_the_referenced_document() -> None:
    seen: list[str] = []
    documents = {WELL_KNOWN: catalog(DEPT_ENTRY), DEPT: catalog(entry())}
    status, view, _ = await outcome_of(resolver(documents=documents, seen=seen, follow_nested=True))
    assert status == "present" and view is not None and view.endpoint == CARD
    assert seen == [WELL_KNOWN, DEPT]  # the relative reference resolved against the catalog's URL


@pytest.mark.asyncio
async def test_follow_nested_read_in_full_can_claim_absence() -> None:
    documents = {WELL_KNOWN: catalog(DEPT_ENTRY), DEPT: catalog(entry("urn:air:agent.example.com:other"))}
    assert await outcome_of(resolver(documents=documents, follow_nested=True)) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_nested_document_that_cannot_be_read_blocks_absence() -> None:
    for served in (httpx.Response(500), httpx.Response(404), httpx.Response(200, json={"not": "a catalog"})):
        documents = {WELL_KNOWN: catalog(DEPT_ENTRY), DEPT: served}
        assert await outcome_of(resolver(documents=documents, follow_nested=True)) == (
            "error",
            None,
            OUTCOME_NESTED_NOT_READ,
        )


@pytest.mark.asyncio
async def test_a_cycle_is_read_once() -> None:
    seen: list[str] = []
    back = {"identifier": "urn:air:agent.example.com:root", "type": CATALOG, "url": WELL_KNOWN}
    documents = {WELL_KNOWN: catalog(DEPT_ENTRY), DEPT: catalog(back, DEPT_ENTRY)}
    assert await outcome_of(resolver(documents=documents, seen=seen, follow_nested=True)) == ("absent", None, "absent")
    assert seen == [WELL_KNOWN, DEPT]


@pytest.mark.asyncio
async def test_depth_and_document_bounds_block_absence_rather_than_guess() -> None:
    documents = {WELL_KNOWN: catalog(DEPT_ENTRY), DEPT: catalog(entry())}
    for bounds in ({"max_depth": 1}, {"max_documents": 1}):
        r = resolver(documents=documents, follow_nested=True, **bounds)
        assert await outcome_of(r) == ("error", None, OUTCOME_NESTED_NOT_READ)
    deep = catalog({"identifier": "urn:x", "type": CATALOG, "data": catalog(entry())})
    assert await outcome_of(resolver(deep, max_depth=1)) == ("error", None, OUTCOME_NESTED_NOT_READ)


@pytest.mark.asyncio
async def test_subject_that_is_a_nested_catalog_by_url() -> None:
    by_url = {"identifier": ID, "type": CATALOG, "url": "/catalogs/dept.json"}
    documents = {WELL_KNOWN: catalog(by_url), DEPT: MULTI["data"]}
    # Not read: the subject is a catalog this resolver holds no copy of.
    assert await outcome_of(resolver(documents=documents)) == ("error", None, OUTCOME_NESTED_NOT_READ)
    _, view, _ = await outcome_of(resolver(documents=documents, follow_nested=True, artifact_type=MCP))
    assert view == RecordView(endpoint=MCP_CARD)


# --- sweep-level --------------------------------------------------------------


def zone(*records: str) -> DnsSvcbResolver:
    async def query(name: str, rdtype: str) -> DnsAnswer:
        return (
            DnsAnswer(svcb=svcb_rows_from_text(*records))
            if name == "agent.example.com."
            else DnsAnswer(rcode="NXDOMAIN")
        )

    return DnsSvcbResolver(query=query, owner_for=lambda agent_id: "agent.example.com")


@pytest.mark.asyncio
async def test_catalog_and_zone_naming_the_same_descriptor_agree() -> None:
    row = f'1 . alpn="a2a" key65400="{CARD}" key65401="{D_B64}" key65402="a2a"'
    results = await Corroborator([resolver(label="catalog"), zone(row)]).check([ID])
    assert all_findings(results) == []
    assert results[0].verdict == "AGREE"


@pytest.mark.asyncio
async def test_catalog_and_zone_naming_different_descriptors_diverge() -> None:
    row = f'1 . alpn="a2a" key65400="https://elsewhere.example/card.json" key65401="{D_B64}"'
    results = await Corroborator([resolver(label="catalog"), zone(row)]).check([ID])
    assert kinds(results) == [ENDPOINT]


@pytest.mark.asyncio
async def test_same_descriptor_different_digest_is_a_digest_finding() -> None:
    row = f'1 . alpn="a2a" key65400="{CARD}" key65401="{"A" * 43}"'
    results = await Corroborator([resolver(label="catalog"), zone(row)]).check([ID])
    assert kinds(results) == [DIGEST]


@pytest.mark.asyncio
async def test_missing_catalog_is_excluded_not_counted_as_an_omission() -> None:
    row = f'1 . alpn="a2a" key65400="{CARD}"'
    missing = resolver(documents={"https://elsewhere.example/": {}}, label="catalog")
    results = await Corroborator([missing, zone(row)]).check([ID])
    assert all_findings(results) == []
    outcomes = {claim.source: claim.outcome for claim in results[0].claims}
    assert outcomes["catalog"] == OUTCOME_NO_CATALOG


def test_fixture_is_valid_json() -> None:
    json.dumps(catalog(MULTI, DEPT_ENTRY, entry()))
