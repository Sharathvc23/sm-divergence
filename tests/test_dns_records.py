"""DnsSvcbResolver / DnsTxtResolver — a zone as one discovery source.

Zone data is written in presentation format and parsed by the same converter the
default network path uses, so the wire-to-row reduction is under test too. The
network itself is replaced by a table of ``(owner, type) -> answer``.

The cases that carry the weight are the negative ones: a failing resolver, an
unreadable row and an unauthenticated answer are not claims of absence; a bare id
is not a DNS name; and two rows that disagree are not this adapter's to choose
between.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from _sweep import all_findings, kinds
from sm_resolver import (
    OMISSION,
    OUTCOME_REFUSED,
    OUTCOME_TIMEOUT,
    OUTCOME_UNPARSEABLE,
    OUTCOME_UNREACHABLE,
    OUTCOME_UNVERIFIABLE,
    SOURCE_EQUIVOCATION,
    Corroborator,
    Status,
)

from sm_divergence.discovery import (
    DIGEST,
    ENDPOINT,
    OUTCOME_AMBIGUOUS_RRSET,
    DnsAnswer,
    DnsSvcbResolver,
    DnsTxtResolver,
    RecordView,
    SvcbRow,
    SvcParamKeyMap,
    normalize_owner,
    svcb_rows_from_text,
    txt_rows_from_text,
)
from sm_divergence.discovery.dns_records import parse_ans_txt

FQDN = "agent.example.com"
CARD = "https://agent.example.com/.well-known/agent-card.json"
D_B64 = "9s_HMOu6_nLBerzY8AS1gJcOWqy_67fWyIMoKtfwqPU"
D_HEX = "f6cfc730ebbafe72c17abcd8f004b580970e5aacbfebb7d6c883282ad7f0a8f5"
D_CANON = "sha256:" + D_HEX

R1 = f'1 . alpn="a2a" port=443 key65400="{CARD}" key65401="{D_B64}" key65402="a2a" key65409="agent-card.json"'
R_MCP = '2 . alpn="h2" key65402="mcp" key65400="https://agent.example.com/mcp.json"'

Zone = dict[tuple[str, str], DnsAnswer]


def svcb(*records: str, authenticated: bool = False) -> DnsAnswer:
    return DnsAnswer(svcb=svcb_rows_from_text(*records), authenticated=authenticated)


def txt(*records: str, authenticated: bool = False) -> DnsAnswer:
    return DnsAnswer(txt=txt_rows_from_text(*records), authenticated=authenticated)


def zone_query(zone: Zone, asked: list[tuple[str, str]] | None = None) -> Any:
    """A table-driven DnsQuery. A name not in the table does not exist."""

    async def query(name: str, rdtype: str) -> DnsAnswer:
        if asked is not None:
            asked.append((name, rdtype))
        return zone.get((name, rdtype), DnsAnswer(rcode="NXDOMAIN"))

    return query


def svcb_resolver(zone: Zone, **kw: Any) -> DnsSvcbResolver:
    return DnsSvcbResolver(query=zone_query(zone), **kw)


def txt_resolver(zone: Zone, **kw: Any) -> DnsTxtResolver:
    return DnsTxtResolver(query=zone_query(zone), **kw)


def at(owner: str, answer: DnsAnswer, rdtype: str = "SVCB") -> Zone:
    return {(owner + ".", rdtype): answer}


async def outcome_of(resolver: Any, agent_id: str = FQDN) -> tuple[Status, RecordView | None, str]:
    result: tuple[Status, RecordView | None, str] = await resolver.resolve_with_outcome(agent_id)
    return result


# --- SVCB: what a row contributes --------------------------------------------


@pytest.mark.asyncio
async def test_s01_descriptor_and_digest_from_one_row() -> None:
    status, view, outcome = await outcome_of(svcb_resolver(at(FQDN, svcb(R1))))
    assert (status, outcome) == ("present", "present")
    assert view is not None
    assert view.endpoint == CARD
    assert view.comparable()[DIGEST] == D_CANON
    assert view.did is None and view.binding() is None


@pytest.mark.asyncio
async def test_s02_service_target_reads_the_service_endpoint() -> None:
    _, view, _ = await outcome_of(svcb_resolver(at(FQDN, svcb(R1)), target="service"))
    assert view is not None
    assert view.comparable()[ENDPOINT] == "https://agent.example.com/"
    # The digest is still the descriptor's: it names a document, not an address.
    assert view.comparable()[DIGEST] == D_CANON


@pytest.mark.asyncio
async def test_s03_target_name_and_port_form_the_service_endpoint() -> None:
    zone = at(FQDN, svcb('1 svc.host.example. alpn="h2" port=8443'))
    _, view, _ = await outcome_of(svcb_resolver(zone, target="service"))
    assert view is not None and view.endpoint == "https://svc.host.example:8443/"


@pytest.mark.asyncio
async def test_path_key_is_read_only_when_mapped() -> None:
    row = '1 . alpn="h2" key65403="/mcp"'
    unmapped = await outcome_of(svcb_resolver(at(FQDN, svcb(row)), target="service"))
    assert unmapped[1] is not None and unmapped[1].endpoint == "https://agent.example.com/"
    mapped = await outcome_of(svcb_resolver(at(FQDN, svcb(row)), target="service", key_map=SvcParamKeyMap(path=65403)))
    assert mapped[1] is not None and mapped[1].endpoint == "https://agent.example.com/mcp"


@pytest.mark.asyncio
async def test_relative_path_value_is_unparseable() -> None:
    zone = at(FQDN, svcb('1 . alpn="h2" key65403="mcp"'))
    status, _, outcome = await outcome_of(svcb_resolver(zone, target="service", key_map=SvcParamKeyMap(path=65403)))
    assert (status, outcome) == ("error", OUTCOME_UNPARSEABLE)


@pytest.mark.asyncio
async def test_s15_well_known_suffix_names_the_descriptor() -> None:
    zone = at(FQDN, svcb('1 . alpn="a2a" key65402="a2a" key65409="agent-card.json"'))
    _, view, _ = await outcome_of(svcb_resolver(zone))
    assert view is not None and view.endpoint == CARD and view.digest is None


@pytest.mark.asyncio
async def test_named_descriptor_wins_over_well_known_suffix() -> None:
    zone = at(FQDN, svcb('1 . alpn="a2a" key65400="https://cards.example/a.json" key65409="agent-card.json"'))
    _, view, _ = await outcome_of(svcb_resolver(zone))
    assert view is not None and view.endpoint == "https://cards.example/a.json"


@pytest.mark.parametrize("suffix", ["a/b.json", "card.json?x=1", "card.json#frag"])
@pytest.mark.asyncio
async def test_well_known_suffix_must_be_one_segment(suffix: str) -> None:
    zone = at(FQDN, svcb(f'1 . alpn="a2a" key65409="{suffix}"'))
    status, _, outcome = await outcome_of(svcb_resolver(zone))
    assert (status, outcome) == ("error", OUTCOME_UNPARSEABLE)


@pytest.mark.asyncio
async def test_s16_row_without_descriptor_contributes_no_endpoint() -> None:
    zone = at(FQDN, svcb('1 . alpn="a2a" port=443 key65402="a2a"'))
    status, view, _ = await outcome_of(svcb_resolver(zone))
    assert status == "present"
    # Never the service address in the descriptor's place.
    assert view is not None and view.endpoint is None


@pytest.mark.asyncio
async def test_s19_unrecognized_digest_is_carried_literally() -> None:
    zone = at(FQDN, svcb(f'1 . alpn="a2a" key65400="{CARD}" key65401="not-a-digest"'))
    _, view, _ = await outcome_of(svcb_resolver(zone))
    assert view is not None and view.comparable()[DIGEST] == "not-a-digest"


@pytest.mark.asyncio
async def test_custom_key_map_reads_other_code_points() -> None:
    zone = at(FQDN, svcb(f'1 . alpn="h2" key65300="{CARD}" key65301="{D_B64}"'))
    keys = SvcParamKeyMap(descriptor=65300, descriptor_digest=65301, agent_protocol=None, well_known=None)
    _, view, _ = await outcome_of(svcb_resolver(zone, key_map=keys))
    assert view is not None and view.endpoint == CARD and view.comparable()[DIGEST] == D_CANON
    # Under the default map those keys mean nothing, so no descriptor is read.
    _, default_view, _ = await outcome_of(svcb_resolver(zone))
    assert default_view is not None and default_view.endpoint is None


# --- SVCB: row selection ------------------------------------------------------


@pytest.mark.asyncio
async def test_s04_protocol_selects_its_row() -> None:
    _, view, _ = await outcome_of(svcb_resolver(at(FQDN, svcb(R1, R_MCP)), protocol="mcp"))
    assert view is not None and view.endpoint == "https://agent.example.com/mcp.json"


@pytest.mark.asyncio
async def test_s05_without_protocol_the_lowest_priority_row_wins() -> None:
    _, view, _ = await outcome_of(svcb_resolver(at(FQDN, svcb(R_MCP, R1))))
    assert view is not None and view.endpoint == CARD


@pytest.mark.asyncio
async def test_s20_agent_protocol_key_decides_over_alpn() -> None:
    zone = at(FQDN, svcb(f'1 . alpn="h2" key65400="{CARD}" key65402="a2a"'))
    assert (await outcome_of(svcb_resolver(zone, protocol="a2a")))[0] == "present"
    # alpn says h2, but the row declares its agent protocol; h2 is not it.
    assert (await outcome_of(svcb_resolver(zone, protocol="h2")))[0] == "absent"


@pytest.mark.asyncio
async def test_s21_alpn_matches_when_no_agent_protocol_is_declared() -> None:
    zone = at(FQDN, svcb(f'1 . alpn="a2a" key65400="{CARD}"'))
    assert (await outcome_of(svcb_resolver(zone, protocol="A2A")))[0] == "present"


@pytest.mark.asyncio
async def test_s22_no_row_for_the_protocol_is_absent() -> None:
    status, view, outcome = await outcome_of(svcb_resolver(at(FQDN, svcb(R1)), protocol="mcp"))
    assert (status, view, outcome) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_s25_equal_priority_rows_that_disagree_are_ambiguous() -> None:
    zone = at(
        FQDN,
        svcb(
            '1 . alpn="a2a" key65400="https://a.example/1.json"', '1 . alpn="a2a" key65400="https://a.example/2.json"'
        ),
    )
    status, view, outcome = await outcome_of(svcb_resolver(zone))
    assert (status, view, outcome) == ("error", None, OUTCOME_AMBIGUOUS_RRSET)


@pytest.mark.asyncio
async def test_equal_priority_rows_that_agree_are_one_claim() -> None:
    zone = at(
        FQDN,
        svcb(f'1 . alpn="h2" key65400="{CARD}"', f'1 . alpn="h3" key65400="{CARD}" port=443'),
    )
    status, view, _ = await outcome_of(svcb_resolver(zone))
    assert status == "present" and view is not None and view.endpoint == CARD


def test_ambiguous_outcome_is_namespaced() -> None:
    # Bare outcome names are reserved for the kernel's seeded values.
    assert "." in OUTCOME_AMBIGUOUS_RRSET


# --- SVCB: mandatory ----------------------------------------------------------


@pytest.mark.asyncio
async def test_s13_row_requiring_an_unknown_key_is_not_a_claim_of_absence() -> None:
    zone = at(FQDN, svcb('1 . mandatory=key65300 alpn="h2" key65300="x"'))
    status, _, outcome = await outcome_of(svcb_resolver(zone))
    assert (status, outcome) == ("error", OUTCOME_UNPARSEABLE)


@pytest.mark.asyncio
async def test_s14_row_requiring_a_mapped_key_is_read() -> None:
    zone = at(FQDN, svcb(f'1 . mandatory=key65400 alpn="h2" key65400="{CARD}"'))
    status, view, _ = await outcome_of(svcb_resolver(zone))
    assert status == "present" and view is not None and view.endpoint == CARD


@pytest.mark.asyncio
async def test_unreadable_row_is_skipped_when_another_row_is_readable() -> None:
    zone = at(
        FQDN,
        svcb('1 . mandatory=key65300 alpn="h2" key65300="x"', f'2 . alpn="a2a" key65400="{CARD}"'),
    )
    status, view, _ = await outcome_of(svcb_resolver(zone))
    assert status == "present" and view is not None and view.endpoint == CARD


# --- SVCB: AliasMode ----------------------------------------------------------


@pytest.mark.asyncio
async def test_s11_alias_is_followed_to_the_primary_owner() -> None:
    zone: Zone = {
        ("agent._agents.example.com.", "SVCB"): svcb("0 agent.example.com."),
        ("agent.example.com.", "SVCB"): svcb('1 . alpn="a2a" key65409="agent-card.json"'),
    }
    status, view, _ = await outcome_of(svcb_resolver(zone), "agent._agents.example.com")
    assert status == "present"
    # The well-known descriptor lives at the owner the ServiceMode row is at.
    assert view is not None and view.endpoint == CARD


@pytest.mark.asyncio
async def test_s12_alias_chain_longer_than_the_bound_is_unparseable() -> None:
    zone: Zone = {
        ("a.example.com.", "SVCB"): svcb("0 b.example.com."),
        ("b.example.com.", "SVCB"): svcb("0 c.example.com."),
        ("c.example.com.", "SVCB"): svcb(R1),
    }
    status, _, outcome = await outcome_of(svcb_resolver(zone), "a.example.com")
    assert (status, outcome) == ("error", OUTCOME_UNPARSEABLE)
    assert (await outcome_of(svcb_resolver(zone, max_alias_hops=2), "a.example.com"))[0] == "present"


@pytest.mark.asyncio
async def test_alias_to_root_means_the_service_does_not_exist() -> None:
    status, view, outcome = await outcome_of(svcb_resolver(at(FQDN, svcb("0 ."))))
    assert (status, view, outcome) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_alias_row_makes_service_rows_in_the_same_rrset_ignored() -> None:
    zone: Zone = {
        (FQDN + ".", "SVCB"): svcb(
            "0 primary.example.com.", '1 . alpn="a2a" key65400="https://ignored.example/x.json"'
        ),
        ("primary.example.com.", "SVCB"): svcb(R1),
    }
    _, view, _ = await outcome_of(svcb_resolver(zone))
    assert view is not None and view.endpoint == CARD


@pytest.mark.asyncio
async def test_two_aliases_to_different_names_are_ambiguous() -> None:
    zone = at(FQDN, svcb("0 one.example.com.", "0 two.example.com."))
    status, _, outcome = await outcome_of(svcb_resolver(zone))
    assert (status, outcome) == ("error", OUTCOME_AMBIGUOUS_RRSET)


@pytest.mark.asyncio
async def test_alias_to_a_name_that_does_not_exist_is_absent() -> None:
    status, _, outcome = await outcome_of(svcb_resolver(at(FQDN, svcb("0 gone.example.com."))))
    assert (status, outcome) == ("absent", "absent")


# --- response classification (shared by both resolvers) -----------------------


def _resolvers(answer: DnsAnswer | Callable[[], Any], **kw: Any) -> list[Any]:
    async def query(name: str, rdtype: str) -> DnsAnswer:
        if callable(answer):
            result: DnsAnswer = await answer()
            return result
        return answer

    return [DnsSvcbResolver(query=query, **kw), DnsTxtResolver(query=query, **kw)]


@pytest.mark.asyncio
async def test_s06_nxdomain_is_absent() -> None:
    for resolver in _resolvers(DnsAnswer(rcode="NXDOMAIN")):
        assert await outcome_of(resolver) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_s07_nodata_is_absent() -> None:
    for resolver in _resolvers(DnsAnswer()):
        assert await outcome_of(resolver) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_s08_timeout_is_not_a_claim() -> None:
    async def slow() -> DnsAnswer:
        await asyncio.sleep(5)
        return DnsAnswer()

    async def raises() -> DnsAnswer:
        raise TimeoutError

    for answer in (slow, raises):
        for resolver in _resolvers(answer, timeout=0.01):
            assert await outcome_of(resolver) == ("error", None, OUTCOME_TIMEOUT)


@pytest.mark.asyncio
async def test_transport_failure_is_unreachable() -> None:
    async def broken() -> DnsAnswer:
        raise OSError("network is unreachable")

    for resolver in _resolvers(broken):
        assert await outcome_of(resolver) == ("error", None, OUTCOME_UNREACHABLE)


@pytest.mark.parametrize(
    ("rcode", "outcome"),
    [("SERVFAIL", OUTCOME_UNREACHABLE), ("OTHER", OUTCOME_UNREACHABLE), ("REFUSED", OUTCOME_REFUSED)],
)
@pytest.mark.asyncio
async def test_s09_s10_failure_rcodes_are_not_claims(rcode: Any, outcome: str) -> None:
    for resolver in _resolvers(DnsAnswer(rcode=rcode)):
        assert await outcome_of(resolver) == ("error", None, outcome)


@pytest.mark.asyncio
async def test_malformed_response_is_unparseable() -> None:
    for resolver in _resolvers(DnsAnswer(malformed=True)):
        assert await outcome_of(resolver) == ("error", None, OUTCOME_UNPARSEABLE)


@pytest.mark.asyncio
async def test_s17_s18_require_dnssec_gates_on_the_authenticated_bit() -> None:
    plain = svcb_resolver(at(FQDN, svcb(R1)), require_dnssec=True)
    assert await outcome_of(plain) == ("error", None, OUTCOME_UNVERIFIABLE)
    signed = svcb_resolver(at(FQDN, svcb(R1, authenticated=True)), require_dnssec=True)
    status, view, _ = await outcome_of(signed)
    assert status == "present" and view is not None and view.endpoint == CARD


@pytest.mark.asyncio
async def test_unauthenticated_denial_is_not_a_claim_of_absence() -> None:
    for resolver in _resolvers(DnsAnswer(rcode="NXDOMAIN"), require_dnssec=True):
        assert await outcome_of(resolver) == ("error", None, OUTCOME_UNVERIFIABLE)
    for resolver in _resolvers(DnsAnswer(rcode="NXDOMAIN", authenticated=True), require_dnssec=True):
        assert await outcome_of(resolver) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_require_dnssec_applies_to_every_alias_hop() -> None:
    zone: Zone = {
        ("leaf.example.com.", "SVCB"): svcb("0 agent.example.com.", authenticated=True),
        ("agent.example.com.", "SVCB"): svcb(R1),
    }
    status, _, outcome = await outcome_of(svcb_resolver(zone, require_dnssec=True), "leaf.example.com")
    assert (status, outcome) == ("error", OUTCOME_UNVERIFIABLE)


@pytest.mark.asyncio
async def test_resolve_never_raises_and_mirrors_resolve_with_outcome() -> None:
    def bad_owner(agent_id: str) -> str:
        raise RuntimeError("no mapping")

    for resolver in (svcb_resolver({}, owner_for=bad_owner), txt_resolver({}, owner_for=bad_owner)):
        assert await resolver.resolve("anything") == ("error", None)
    assert await svcb_resolver(at(FQDN, svcb(R1))).resolve(FQDN) == ("present", RecordView(endpoint=CARD, digest=D_B64))


# --- owner names --------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("agent.example.com", "agent.example.com"),
        ("Agent.Example.COM.", "agent.example.com"),
        ("  agent.example.com  ", "agent.example.com"),
        ("_a2a._agents.example.com", "_a2a._agents.example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("agent-1", None),  # a bare id is not a DNS name
        ("not a host", None),
        ("-bad.example.com", None),
        ("a..example.com", None),
        ("", None),
        ("a" * 64 + ".example.com", None),
        (".".join(["a" * 60] * 5), None),  # longer than 253 octets
    ],
)
def test_normalize_owner(given: str, expected: str | None) -> None:
    assert normalize_owner(given) == expected


@pytest.mark.asyncio
async def test_s23_query_name_is_absolute_and_lowercased() -> None:
    asked: list[tuple[str, str]] = []
    resolver = DnsSvcbResolver(query=zone_query(at(FQDN, svcb(R1)), asked))
    assert (await outcome_of(resolver, "Agent.Example.COM."))[0] == "present"
    assert asked == [("agent.example.com.", "SVCB")]


@pytest.mark.asyncio
async def test_s24_unusable_owner_sends_no_query() -> None:
    asked: list[tuple[str, str]] = []
    for resolver in (DnsSvcbResolver(query=zone_query({}, asked)), DnsTxtResolver(query=zone_query({}, asked))):
        for agent_id in ("agent-1", "not a host"):
            # An id with no DNS correspondence is an error, never a false absent.
            assert await outcome_of(resolver, agent_id) == ("error", None, OUTCOME_UNPARSEABLE)
    assert asked == []


@pytest.mark.asyncio
async def test_owner_for_maps_the_watch_id_to_the_fqdn() -> None:
    resolver = svcb_resolver(at(FQDN, svcb(R1)), owner_for=lambda agent_id: {"agent-1": FQDN}[agent_id])
    assert (await outcome_of(resolver, "agent-1"))[0] == "present"


def test_labels_and_vantage() -> None:
    assert svcb_resolver({}).label == "dns-svcb"
    assert txt_resolver({}).label == "dns-txt"
    resolver = svcb_resolver({}, label="example-zone", vantage="resolver-a")
    assert resolver.label == "example-zone" and resolver.vantage == "resolver-a"


# --- presentation-format parsing ----------------------------------------------


def test_s26_named_key_without_a_code_point_does_not_parse() -> None:
    with pytest.raises(Exception):  # noqa: B017 - the parser's own error type
        svcb_rows_from_text('1 . alpn="a2a" proto=a2a')


def test_row_reduction_keeps_registered_and_private_keys_apart() -> None:
    (row,) = svcb_rows_from_text(
        '1 svc.example.com. mandatory=alpn,key65400 alpn="h2,a2a" port=8443 ipv4hint=192.0.2.1 key65400="x"'
    )
    assert row == SvcbRow(
        priority=1,
        target="svc.example.com.",
        alpn=("h2", "a2a"),
        port=8443,
        mandatory=(1, 65400),
        params={65400: "x"},
    )


def test_private_key_value_that_is_not_text_does_not_reduce() -> None:
    with pytest.raises(UnicodeDecodeError):
        svcb_rows_from_text(r'1 . key65400="\255\254"')


# --- TXT ----------------------------------------------------------------------

T_A2A = '"v=ans1; version=v1; p=a2a; mode=direct; url=https://agent.example.com/a2a"'
T_MCP = '"v=ans1; version=v1; p=mcp; mode=direct; url=https://agent.example.com/mcp"'
TXT_OWNER = "_ans." + FQDN


@pytest.mark.asyncio
async def test_t01_one_row_yields_the_endpoint() -> None:
    asked: list[tuple[str, str]] = []
    resolver = DnsTxtResolver(query=zone_query(at(TXT_OWNER, txt(T_A2A), "TXT"), asked))
    status, view, outcome = await outcome_of(resolver)
    assert (status, outcome) == ("present", "present")
    assert view == RecordView(endpoint="https://agent.example.com/a2a")
    assert asked == [("_ans.agent.example.com.", "TXT")]


@pytest.mark.asyncio
async def test_t02_unrelated_txt_data_is_ignored() -> None:
    zone = at(TXT_OWNER, txt('"google-site-verification=abc"', '"v=spf1 -all"'), "TXT")
    assert await outcome_of(txt_resolver(zone)) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_t03_protocol_selects_its_row() -> None:
    zone = at(TXT_OWNER, txt(T_A2A, T_MCP), "TXT")
    _, view, _ = await outcome_of(txt_resolver(zone, protocol="mcp"))
    assert view is not None and view.endpoint == "https://agent.example.com/mcp"
    assert (await outcome_of(txt_resolver(zone, protocol="x-http")))[0] == "absent"


@pytest.mark.asyncio
async def test_t04_character_strings_are_joined() -> None:
    split = '"v=ans1; version=v1; p=a2a; mode=direct; url=https://agent.exa" "mple.com/a2a"'
    _, view, _ = await outcome_of(txt_resolver(at(TXT_OWNER, txt(split), "TXT")))
    assert view is not None and view.endpoint == "https://agent.example.com/a2a"


@pytest.mark.parametrize(
    "record",
    [
        '"v=ans1; version=v1; p=a2a; mode=direct"',
        '"v=ans1; p=a2a; url=ftp://agent.example.com/a2a"',
        '"v=ans1; p=a2a; url=/relative"',
    ],
)
@pytest.mark.asyncio
async def test_t05_row_without_a_usable_url_is_unparseable(record: str) -> None:
    status, _, outcome = await outcome_of(txt_resolver(at(TXT_OWNER, txt(record), "TXT")))
    assert (status, outcome) == ("error", OUTCOME_UNPARSEABLE)


@pytest.mark.asyncio
async def test_t07_rows_for_two_protocols_need_a_protocol_to_choose() -> None:
    zone = at(TXT_OWNER, txt(T_A2A, T_MCP), "TXT")
    status, _, outcome = await outcome_of(txt_resolver(zone))
    assert (status, outcome) == ("error", OUTCOME_AMBIGUOUS_RRSET)


@pytest.mark.asyncio
async def test_txt_require_dnssec() -> None:
    zone = at(TXT_OWNER, txt(T_A2A), "TXT")
    assert (await outcome_of(txt_resolver(zone, require_dnssec=True)))[2] == OUTCOME_UNVERIFIABLE
    signed = at(TXT_OWNER, txt(T_A2A, authenticated=True), "TXT")
    assert (await outcome_of(txt_resolver(signed, require_dnssec=True)))[0] == "present"


def test_parse_ans_txt() -> None:
    assert parse_ans_txt("v=ans1; Version=v1 ;p=a2a;url=https://a.example/x?y=1;z=2") == {
        "v": "ans1",
        "version": "v1",
        "p": "a2a",
        "url": "https://a.example/x?y=1;z=2",
    }
    assert parse_ans_txt("just some text") == {}
    assert parse_ans_txt("") == {}


# --- sweep-level: a zone beside a registry ------------------------------------


class _Fixed:
    """A source that always answers with one view (or absence)."""

    def __init__(self, label: str, view: RecordView | None, vantage: str | None = None) -> None:
        self._label = label
        self._view = view
        self.vantage = vantage

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        return ("absent", None) if self._view is None else ("present", self._view)


@pytest.mark.asyncio
async def test_k01_same_document_spelled_two_ways_is_no_finding() -> None:
    zone = svcb_resolver(at(FQDN, svcb(R1)))
    registry = _Fixed("registry", RecordView(endpoint=CARD + "#top", digest="sha256:" + D_HEX.upper()))
    results = await Corroborator([zone, registry]).check([FQDN])
    assert all_findings(results) == []


@pytest.mark.asyncio
async def test_k02_same_address_different_document_is_a_digest_finding() -> None:
    zone = svcb_resolver(at(FQDN, svcb(R1)))
    registry = _Fixed("registry", RecordView(endpoint=CARD, digest="sha256:" + "0" * 64))
    results = await Corroborator([zone, registry]).check([FQDN])
    assert kinds(results) == [DIGEST]


@pytest.mark.asyncio
async def test_k03_zone_answering_differently_by_resolver_is_equivocation() -> None:
    other = '1 . alpn="a2a" key65400="https://evil.example/card.json" key65402="a2a"'
    here = svcb_resolver(at(FQDN, svcb(R1)), label="zone", vantage="resolver-a")
    there = svcb_resolver(at(FQDN, svcb(other)), label="zone", vantage="resolver-b")
    results = await Corroborator([here, there]).check([FQDN])
    assert SOURCE_EQUIVOCATION in kinds(results)


@pytest.mark.asyncio
async def test_k04_zone_absent_beside_a_registry_present_is_an_omission() -> None:
    zone = svcb_resolver({})
    registry = _Fixed("registry", RecordView(endpoint=CARD))
    results = await Corroborator([zone, registry]).check([FQDN])
    assert kinds(results) == [OMISSION]


@pytest.mark.asyncio
async def test_failing_zone_is_excluded_not_counted_as_an_omission() -> None:
    async def servfail(name: str, rdtype: str) -> DnsAnswer:
        return DnsAnswer(rcode="SERVFAIL")

    zone = DnsSvcbResolver(query=servfail)
    registry = _Fixed("registry", RecordView(endpoint=CARD))
    results = await Corroborator([zone, registry]).check([FQDN])
    assert all_findings(results) == []


@pytest.mark.asyncio
async def test_outcome_reaches_the_claim() -> None:
    zone = at(
        FQDN,
        svcb(
            '1 . alpn="a2a" key65400="https://a.example/1.json"', '1 . alpn="a2a" key65400="https://a.example/2.json"'
        ),
    )
    results = await Corroborator([svcb_resolver(zone), _Fixed("registry", RecordView(endpoint=CARD))]).check([FQDN])
    outcomes = {claim.source: claim.outcome for claim in results[0].claims}
    assert outcomes["dns-svcb"] == OUTCOME_AMBIGUOUS_RRSET
