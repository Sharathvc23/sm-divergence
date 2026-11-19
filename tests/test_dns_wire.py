"""The default DNS network path, exercised over the wire.

``DnspythonQuery`` is asked real questions through a loopback UDP server that
answers from a table, so the reduction from a DNS message to a ``DnsAnswer`` —
rcode, the authenticated bit, record conversion, timeout — is tested against
actual wire data rather than against the fake the resolver tests use.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from typing import Any

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import httpx
import pytest
import pytest_asyncio

from sm_divergence.discovery import (
    DnsAnswer,
    DnspythonQuery,
    DnsSvcbResolver,
    DnsTxtResolver,
    DohQuery,
    RecordView,
    SvcbRow,
)

CARD = "https://agent.example.com/.well-known/agent-card.json"
D_B64 = "9s_HMOu6_nLBerzY8AS1gJcOWqy_67fWyIMoKtfwqPU"
R1 = f'1 . alpn="a2a" port=443 key65400="{CARD}" key65401="{D_B64}" key65402="a2a" key65409="agent-card.json"'
T_A2A = '"v=ans1; version=v1; p=a2a; mode=direct; url=https://agent.exa" "mple.com/a2a"'

# (owner, type) -> records in presentation format. Anything else is NXDOMAIN.
RECORDS: dict[tuple[str, str], list[str]] = {
    ("agent.example.com.", "SVCB"): [R1, '2 svc.example.com. alpn="h2" port=8443 key65402="mcp"'],
    ("signed.example.com.", "SVCB"): [R1],
    ("leaf.example.com.", "SVCB"): ["0 agent.example.com."],
    ("binary.example.com.", "SVCB"): [r'1 . key65400="\255\254"'],
    ("nodata.example.com.", "SVCB"): [],
    ("_ans.agent.example.com.", "TXT"): [T_A2A, '"v=spf1 -all"'],
}
RCODES = {"servfail.example.com.": dns.rcode.SERVFAIL, "refused.example.com.": dns.rcode.REFUSED}
AUTHENTICATED = {"signed.example.com.", "signed-gone.example.com."}
SILENT = "silent.example.com."


def answer(query: dns.message.Message) -> dns.message.Message | None:
    question = query.question[0]
    name = question.name.to_text().lower()
    rdtype = dns.rdatatype.to_text(question.rdtype)
    if name == SILENT:
        return None
    response = dns.message.make_response(query)
    response.flags |= dns.flags.RA
    if name in AUTHENTICATED:
        response.flags |= dns.flags.AD
    if name in RCODES:
        response.set_rcode(RCODES[name])
        return response
    records = RECORDS.get((name, rdtype))
    if records is None:
        if not any(owner == name for owner, _ in RECORDS):
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response
    if records:
        response.answer.append(dns.rrset.from_text(question.name, 300, "IN", rdtype, *records))
    return response


class _Server(asyncio.DatagramProtocol):
    def __init__(self, handler: Callable[[dns.message.Message], dns.message.Message | None]) -> None:
        self.handler = handler
        self.transport: Any = None

    def connection_made(self, transport: Any) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Any) -> None:
        response = self.handler(dns.message.from_wire(data))
        if response is not None:
            self.transport.sendto(response.to_wire(), addr)


@pytest_asyncio.fixture
async def query() -> AsyncIterator[DnspythonQuery]:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: _Server(answer), local_addr=("127.0.0.1", 0))
    port = transport.get_extra_info("sockname")[1]
    try:
        yield DnspythonQuery(["127.0.0.1"], port=port, timeout=0.5)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_svcb_rrset_is_reduced_to_rows(query: DnspythonQuery) -> None:
    result = await query("agent.example.com.", "SVCB")
    assert result.rcode == "NOERROR" and not result.malformed and not result.authenticated
    assert sorted(result.svcb, key=lambda row: row.priority) == [
        SvcbRow(
            priority=1,
            target=".",
            alpn=("a2a",),
            port=443,
            params={65400: CARD, 65401: D_B64, 65402: "a2a", 65409: "agent-card.json"},
        ),
        SvcbRow(priority=2, target="svc.example.com.", alpn=("h2",), port=8443, params={65402: "mcp"}),
    ]


@pytest.mark.asyncio
async def test_txt_character_strings_are_joined(query: DnspythonQuery) -> None:
    result = await query("_ans.agent.example.com.", "TXT")
    assert sorted(result.txt) == [
        "v=ans1; version=v1; p=a2a; mode=direct; url=https://agent.example.com/a2a",
        "v=spf1 -all",
    ]


@pytest.mark.asyncio
async def test_nxdomain_nodata_and_the_authenticated_bit(query: DnspythonQuery) -> None:
    assert await query("gone.example.com.", "SVCB") == DnsAnswer(rcode="NXDOMAIN")
    assert await query("signed-gone.example.com.", "SVCB") == DnsAnswer(rcode="NXDOMAIN", authenticated=True)
    assert await query("nodata.example.com.", "SVCB") == DnsAnswer()
    # The name exists, with no record of the type asked for.
    assert await query("agent.example.com.", "TXT") == DnsAnswer()
    assert (await query("signed.example.com.", "SVCB")).authenticated is True


@pytest.mark.asyncio
async def test_failure_rcodes(query: DnspythonQuery) -> None:
    assert (await query("servfail.example.com.", "SVCB")).rcode == "SERVFAIL"
    assert (await query("refused.example.com.", "SVCB")).rcode == "REFUSED"


@pytest.mark.asyncio
async def test_silence_is_a_timeout(query: DnspythonQuery) -> None:
    with pytest.raises(TimeoutError):
        await query(SILENT, "SVCB")


@pytest.mark.asyncio
async def test_record_that_cannot_be_reduced_is_malformed(query: DnspythonQuery) -> None:
    assert (await query("binary.example.com.", "SVCB")).malformed is True


@pytest.mark.asyncio
async def test_resolvers_end_to_end_over_the_wire(query: DnspythonQuery) -> None:
    svcb = DnsSvcbResolver(query=query)
    status, view, outcome = await svcb.resolve_with_outcome("agent.example.com")
    assert (status, outcome) == ("present", "present")
    assert view is not None and view.endpoint == CARD
    assert view.comparable()["digest"] == "sha256:f6cfc730ebbafe72c17abcd8f004b580970e5aacbfebb7d6c883282ad7f0a8f5"

    # The second row, by agent protocol, at its own target and port.
    mcp = DnsSvcbResolver(query=query, protocol="mcp", target="service")
    assert (await mcp.resolve("agent.example.com"))[1] == RecordView(endpoint="https://svc.example.com:8443/")

    assert (await svcb.resolve("leaf.example.com"))[0] == "present"  # alias followed
    assert await svcb.resolve_with_outcome("gone.example.com") == ("absent", None, "absent")
    assert await svcb.resolve_with_outcome("servfail.example.com") == ("error", None, "unreachable")
    assert await svcb.resolve_with_outcome("refused.example.com") == ("error", None, "refused")
    assert await svcb.resolve_with_outcome("silent.example.com") == ("error", None, "timeout")
    assert await svcb.resolve_with_outcome("binary.example.com") == ("error", None, "unparseable")

    strict = DnsSvcbResolver(query=query, require_dnssec=True)
    assert await strict.resolve_with_outcome("agent.example.com") == ("error", None, "unverifiable")
    assert (await strict.resolve("signed.example.com"))[0] == "present"

    txt = DnsTxtResolver(query=query)
    status, view, _ = await txt.resolve_with_outcome("agent.example.com")
    assert status == "present" and view is not None and view.endpoint == "https://agent.example.com/a2a"


def test_default_query_is_built_from_nameservers() -> None:
    resolver = DnsSvcbResolver(nameservers=["192.0.2.53"], timeout=1.0)
    assert resolver.label == "dns-svcb"


# --- DNS over HTTPS -----------------------------------------------------------


def doh(
    handler: Callable[[dns.message.Message], dns.message.Message | None], seen: list[httpx.Request] | None = None
) -> DohQuery:
    def transport(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        response = handler(dns.message.from_wire(request.content))
        if response is None:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, content=response.to_wire(), headers={"content-type": "application/dns-message"})

    return DohQuery("https://resolver.example/dns-query", transport=httpx.MockTransport(transport), timeout=0.5)


@pytest.mark.asyncio
async def test_doh_request_is_a_wire_format_post() -> None:
    seen: list[httpx.Request] = []
    result = await doh(answer, seen)("_ans.agent.example.com.", "TXT")
    assert "v=spf1 -all" in result.txt
    (request,) = seen
    assert request.method == "POST" and str(request.url) == "https://resolver.example/dns-query"
    assert request.headers["content-type"] == "application/dns-message"
    sent = dns.message.from_wire(request.content)
    assert sent.id == 0 and sent.flags & dns.flags.AD
    assert sent.question[0].name.to_text() == "_ans.agent.example.com."


@pytest.mark.asyncio
async def test_doh_answers_reduce_like_the_udp_path() -> None:
    query = doh(answer)
    assert len((await query("agent.example.com.", "SVCB")).svcb) == 2
    assert await query("gone.example.com.", "SVCB") == DnsAnswer(rcode="NXDOMAIN")
    assert await query("signed-gone.example.com.", "SVCB") == DnsAnswer(rcode="NXDOMAIN", authenticated=True)
    assert await query("nodata.example.com.", "SVCB") == DnsAnswer()
    assert (await query("signed.example.com.", "SVCB")).authenticated is True
    assert (await query("servfail.example.com.", "SVCB")).rcode == "SERVFAIL"
    assert (await query("refused.example.com.", "SVCB")).rcode == "REFUSED"
    assert (await query("binary.example.com.", "SVCB")).malformed is True


@pytest.mark.asyncio
async def test_doh_follows_a_cname_within_the_response() -> None:
    def aliased(query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        name = query.question[0].name
        response.answer.append(dns.rrset.from_text(name, 300, "IN", "CNAME", "real.example.net."))
        response.answer.append(
            dns.rrset.from_text("real.example.net.", 300, "IN", "TXT", '"v=ans1; url=https://a.example/x"')
        )
        return response

    assert (await doh(aliased)("_ans.agent.example.com.", "TXT")).txt == ("v=ans1; url=https://a.example/x",)


@pytest.mark.asyncio
async def test_doh_failures_are_not_answers() -> None:
    with pytest.raises(TimeoutError):
        await doh(answer)(SILENT, "SVCB")

    def http_500(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    def garbage(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>not dns</html>")

    broken = DohQuery("https://resolver.example/dns-query", transport=httpx.MockTransport(http_500))
    with pytest.raises(ConnectionError):
        await broken("agent.example.com.", "SVCB")
    unreadable = DohQuery("https://resolver.example/dns-query", transport=httpx.MockTransport(garbage))
    assert (await unreadable("agent.example.com.", "SVCB")).malformed is True


@pytest.mark.asyncio
async def test_resolvers_over_doh_end_to_end() -> None:
    svcb = DnsSvcbResolver(query=doh(answer))
    status, view, _ = await svcb.resolve_with_outcome("agent.example.com")
    assert status == "present" and view is not None and view.endpoint == CARD
    assert await svcb.resolve_with_outcome("silent.example.com") == ("error", None, "timeout")
    broken = DnsSvcbResolver(
        query=DohQuery(
            "https://resolver.example/dns-query", transport=httpx.MockTransport(lambda r: httpx.Response(502))
        )
    )
    assert await broken.resolve_with_outcome("agent.example.com") == ("error", None, "unreachable")
