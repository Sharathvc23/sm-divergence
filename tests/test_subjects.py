"""SubjectMap — per-source names, and the rule that a missing name is not a claim.

The second half is the point: a subject one source cannot be asked about must be
excluded from that source, not reported as absent from it. Every resolver that
takes a name callable is checked for that here, beside a source that does hold
the subject, so a regression would show up as a false omission finding.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from _sweep import all_findings
from sm_resolver import Corroborator, Status

from sm_divergence.discovery import (
    AnsLogResolver,
    AnsV2Resolver,
    CatalogResolver,
    DnsAnswer,
    DnsSvcbResolver,
    DnsTxtResolver,
    DnsZoneResolver,
    RecordView,
    SubjectMap,
)

SUBJECTS = SubjectMap(
    {
        "support-agent": {
            "fqdn": "agent.example.com",
            "catalog": "urn:air:example.com:support",
            "log": "3f0c1a52-6b0e-4d57-9a44-2f6f0d1e7c11",
        },
        "billing-agent": {"fqdn": "billing.example.com"},
    }
)


def test_names_are_looked_up_by_kind() -> None:
    assert SUBJECTS.ids() == ["support-agent", "billing-agent"]
    assert SUBJECTS.name("fqdn")("support-agent") == "agent.example.com"
    assert SUBJECTS.name("catalog")("support-agent") == "urn:air:example.com:support"
    assert SUBJECTS.kinds("billing-agent") == ["fqdn"]


def test_a_missing_name_or_subject_raises() -> None:
    with pytest.raises(KeyError):
        SUBJECTS.name("catalog")("billing-agent")
    with pytest.raises(KeyError):
        SUBJECTS.name("fqdn")("unknown-agent")


def test_default_kinds_fall_back_to_the_watch_id() -> None:
    by_fqdn = SubjectMap({"agent.example.com": {"catalog": "urn:air:example.com:support"}}, default=("fqdn",))
    assert by_fqdn.name("fqdn")("agent.example.com") == "agent.example.com"
    assert by_fqdn.name("catalog")("agent.example.com") == "urn:air:example.com:support"
    with pytest.raises(KeyError):
        by_fqdn.name("log")("agent.example.com")
    # A default never invents a subject that is not in the map.
    with pytest.raises(KeyError):
        by_fqdn.name("fqdn")("other.example.com")


@pytest.mark.parametrize("bad", ["", 7, None])
def test_an_empty_or_non_string_name_is_refused_at_construction(bad: Any) -> None:
    with pytest.raises(ValueError):
        SubjectMap({"support-agent": {"fqdn": bad}})


def test_the_map_does_not_alias_the_callers_data() -> None:
    names = {"fqdn": "agent.example.com"}
    subjects = SubjectMap({"support-agent": names})
    names["fqdn"] = "changed.example.com"
    assert subjects.name("fqdn")("support-agent") == "agent.example.com"


# --- a missing name is not a claim --------------------------------------------


def no_network() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"a request was sent for an unmapped subject: {request.url}")

    return httpx.MockTransport(handler)


async def no_dns(name: str, rdtype: str) -> DnsAnswer:
    raise AssertionError(f"a query was sent for an unmapped subject: {name}")


class _Holds:
    """A source that does hold every subject."""

    label = "registry"
    vantage = None

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        return "present", RecordView(endpoint="https://agent.example.com/card.json")


UNMAPPED = SubjectMap({"support-agent": {}}).name("anything")

RESOLVERS = [
    lambda: DnsSvcbResolver(owner_for=UNMAPPED, query=no_dns),
    lambda: DnsTxtResolver(owner_for=UNMAPPED, query=no_dns),
    lambda: DnsZoneResolver(owner_for=UNMAPPED, query=no_dns),
    lambda: CatalogResolver("https://example.com", identifier_for=UNMAPPED, transport=no_network()),
    lambda: AnsLogResolver("https://log.example", agent_id_for=UNMAPPED, transport=no_network()),
    lambda: AnsLogResolver("https://log.example", owner_for=UNMAPPED, badge_query=no_dns, transport=no_network()),
    lambda: AnsV2Resolver("https://ans.example", ansname_for=UNMAPPED, transport=no_network()),
]


@pytest.mark.parametrize("make", RESOLVERS)
@pytest.mark.asyncio
async def test_an_unmapped_subject_is_an_error_and_nothing_is_sent(make: Any) -> None:
    status, view = await make().resolve("support-agent")
    assert (status, view) == ("error", None)


@pytest.mark.parametrize("make", RESOLVERS)
@pytest.mark.asyncio
async def test_an_unmapped_subject_is_never_an_omission_finding(make: Any) -> None:
    results = await Corroborator([make(), _Holds()]).check(["support-agent"])
    assert all_findings(results) == []
