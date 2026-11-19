"""AnsLogResolver — an Agent Name Service transparency log as a source.

A registration is sealed in a log that anyone may read. Its *badge* for an agent
is the latest sealed event, and that event attests the DNS records the agent's
zone held when it was sealed. So the log can be asked what it claims about a
known subject without any credential:

    GET {log_url}/v1/agents/{agentId}  →  the badge

and the attested records are reduced by the same rules ``DnsSvcbResolver`` and
``DnsTxtResolver`` apply to a live zone. A log and a zone that disagree about one
agent — a record changed after it was sealed, or a zone answering differently
from what was registered — then surface as an ordinary divergence.

**Which entry to ask for.** The log files an agent under its own ``agentId``.
Either the caller supplies the mapping (``agent_id_for``), or the resolver reads
the ``v=ans-badge1`` TXT row at ``_ans-badge.{fqdn}``, which names the log and
the entry. A badge row that names a log other than the one configured is
``error``/``unverifiable``: provenance from another log is not a claim by this
one. No badge row is ``error`` too — the log was never asked, so it claimed
nothing.

**Status.** ``ACTIVE``, ``WARNING`` and ``DEPRECATED`` are live registrations.
``REVOKED`` and ``EXPIRED`` are ``error`` with the matching outcome: the log
holds no current binding, which is neither a claim of absence nor a value to
compare.

**The subject must match.** When ``owner_for`` is set, an entry whose attested
host is not the expected FQDN is ``error``/``unverifiable`` — a source must not
dress one agent's record as another's.

**What is not verified.** The badge's signatures, its inclusion proof and the
log's receipt are not checked here. The view is the log's claim, compared like
any registry's unsigned ``endpoint``; it carries no ``did``.

Needs the ``dns`` extra: attested records are zone-file text.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from typing import Any, Literal

import httpx
from sm_resolver import (
    OUTCOME_REFUSED,
    OUTCOME_TIMEOUT,
    OUTCOME_UNPARSEABLE,
    OUTCOME_UNREACHABLE,
    OUTCOME_UNVERIFIABLE,
    Status,
)

from .dns_records import (
    ANS_TXT_PREFIX,
    DEFAULT_KEY_MAP,
    OUTCOME_AMBIGUOUS_RRSET,
    DnspythonQuery,
    DnsQuery,
    OwnerFn,
    SvcParamKeyMap,
    _DnsResolverBase,
    _require_dnspython,
    identity_owner,
    normalize_owner,
    parse_ans_txt,
    reduce_ans_txt,
    reduce_svcb_rows,
    svcb_rows_from_text,
    txt_rows_from_text,
)
from .known_subject import OUTCOME_EXPIRED, OUTCOME_REVOKED
from .views import RecordView, normalize_endpoint

AgentIdFn = Callable[[str], str]

BADGE_PATH = "/v1/agents/{id}"
BADGE_TXT_PREFIX = "_ans-badge."
BADGE_TXT_VERSION = "ans-badge1"

# The zone names no log entry for the subject, so the log could not be asked.
OUTCOME_NO_BADGE = "ai.stellarminds.ans.no-badge"

_LIVE_STATUSES = frozenset({"ACTIVE", "WARNING", "DEPRECATED"})
_BADGE_URL = re.compile(r"^(?P<base>(?i:https?)://.+?)/v1/agents/(?P<agent_id>[^/?#]+)/?$")


def split_badge_url(url: str) -> tuple[str, str] | None:
    """Split a badge row's ``url`` into ``(log base URL, agentId)``; ``None`` if it is not one."""
    match = _BADGE_URL.match(url.strip())
    if match is None:
        return None
    return match.group("base"), match.group("agent_id")


def _same_log(a: str, b: str) -> bool:
    return normalize_endpoint(a.rstrip("/")) == normalize_endpoint(b.rstrip("/"))


def _zone_text(data: str, rdtype: str) -> str:
    """One attested TXT value as plain text, whether stored quoted or raw."""
    if rdtype == "TXT" and data.lstrip().startswith('"'):
        return txt_rows_from_text(data)[0]
    return data


class AnsLogResolver:
    """Resolve a canonical id through one transparency log's public badge route.

    ``log_url`` is the log's base URL. ``agent_id_for`` maps the canonical watch
    id to the log's ``agentId``; when it is ``None`` the entry is located through
    the ``_ans-badge`` TXT row at the FQDN ``owner_for`` returns. ``protocol``,
    ``target`` and ``key_map`` are as for ``DnsSvcbResolver`` and are applied to
    the records the log attests. ``badge_query`` replaces the DNS lookup of the
    badge row, and ``transport`` the HTTP path, for tests. ``vantage`` is the
    observation context; run two instances with the same ``label`` and different
    vantages to detect a log that answers differently by context.
    """

    def __init__(
        self,
        log_url: str,
        *,
        agent_id_for: AgentIdFn | None = None,
        owner_for: OwnerFn | None = None,
        protocol: str | None = None,
        target: Literal["descriptor", "service"] = "descriptor",
        key_map: SvcParamKeyMap = DEFAULT_KEY_MAP,
        badge_path: str = BADGE_PATH,
        badge_query: DnsQuery | None = None,
        nameservers: Sequence[str] | None = None,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
        vantage: str | None = None,
    ) -> None:
        _require_dnspython()
        self.log_url = log_url.rstrip("/")
        self.agent_id_for = agent_id_for
        self.owner_for = owner_for
        self.protocol = protocol.lower() if protocol is not None else None
        self.target = target
        self.key_map = key_map
        self.badge_path = badge_path
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.log_url
        self.vantage = vantage
        self._locator: _BadgeLocator | None = None
        if agent_id_for is None:
            query = badge_query if badge_query is not None else DnspythonQuery(nameservers, timeout=timeout)
            self._locator = _BadgeLocator(owner_for or identity_owner, query, timeout)

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        status, view, _ = await self.resolve_with_outcome(agent_id)
        return status, view

    async def resolve_with_outcome(self, agent_id: str) -> tuple[Status, RecordView | None, str]:
        """Never raises. ``present``/``absent`` use their status as outcome."""
        expected_host: str | None = None
        if self.owner_for is not None or self._locator is not None:
            try:
                expected_host = normalize_owner((self.owner_for or identity_owner)(agent_id))
            except Exception:
                expected_host = None
            if expected_host is None:
                return "error", None, OUTCOME_UNPARSEABLE

        if self.agent_id_for is not None:
            try:
                entry = self.agent_id_for(agent_id)
            except Exception:
                return "error", None, OUTCOME_UNPARSEABLE
        else:
            assert self._locator is not None and expected_host is not None
            located, outcome = await self._locator.locate(expected_host)
            if located is None:
                return "error", None, outcome
            base, entry = located
            if not _same_log(base, self.log_url):
                return "error", None, OUTCOME_UNVERIFIABLE
        if not entry or "/" in entry:
            return "error", None, OUTCOME_UNPARSEABLE

        try:
            async with httpx.AsyncClient(transport=self._transport) as client:
                resp = await client.get(
                    self.log_url + self.badge_path.replace("{id}", entry),
                    headers={"Accept": "application/json"},
                    timeout=self.timeout,
                )
        except httpx.TimeoutException:
            return "error", None, OUTCOME_TIMEOUT
        except Exception:
            return "error", None, OUTCOME_UNREACHABLE

        if resp.status_code == 404:
            return "absent", None, "absent"
        if resp.status_code in (401, 403):
            return "error", None, OUTCOME_REFUSED
        if resp.status_code != 200:
            return "error", None, OUTCOME_UNREACHABLE
        try:
            badge = resp.json()
        except Exception:
            return "error", None, OUTCOME_UNPARSEABLE
        try:
            return self._claim(badge, expected_host)
        except Exception:
            # A badge this adapter cannot read is not a claim of absence.
            return "error", None, OUTCOME_UNPARSEABLE

    def _claim(self, badge: Any, expected_host: str | None) -> tuple[Status, RecordView | None, str]:
        if not isinstance(badge, dict):
            return "error", None, OUTCOME_UNPARSEABLE
        status = badge.get("status")
        if status == "REVOKED":
            return "error", None, OUTCOME_REVOKED
        if status == "EXPIRED":
            return "error", None, OUTCOME_EXPIRED
        if status not in _LIVE_STATUSES:
            return "error", None, OUTCOME_UNPARSEABLE

        event = badge["payload"]["producer"]["event"]
        host = normalize_owner(event["agent"]["host"])
        if host is None:
            return "error", None, OUTCOME_UNPARSEABLE
        if expected_host is not None and host != expected_host:
            return "error", None, OUTCOME_UNVERIFIABLE

        attestations = event.get("attestations") or {}
        records = attestations.get("dnsRecordsProvisioned") or []
        svcb: list[str] = []
        txt: list[str] = []
        for record in records:
            name = normalize_owner(str(record["name"]))
            rdtype = str(record["type"]).upper()
            if rdtype == "SVCB" and name == host:
                svcb.append(str(record["data"]))
            elif rdtype == "TXT" and name == ANS_TXT_PREFIX + host:
                txt.append(_zone_text(str(record["data"]), rdtype))

        if svcb:
            claim = reduce_svcb_rows(
                svcb_rows_from_text(*svcb), host, protocol=self.protocol, target=self.target, key_map=self.key_map
            )
        elif txt:
            claim = reduce_ans_txt(txt, protocol=self.protocol)
        else:
            # A live registration that attests no discovery record: the agent is
            # known to the log, with nothing to compare.
            claim = ("present", RecordView(), "present")

        state, view, outcome = claim
        if view is not None and view.digest is None:
            pinned = self._pinned_digest(attestations.get("metadataHashes"))
            if pinned is not None:
                view = RecordView(endpoint=view.endpoint, digest=pinned)
        return state, view, outcome

    def _pinned_digest(self, hashes: Any) -> str | None:
        """The descriptor digest the event attests per protocol, when it names exactly one."""
        if not isinstance(hashes, dict) or not hashes:
            return None
        if self.protocol is not None:
            for name, value in hashes.items():
                if str(name).lower() == self.protocol and isinstance(value, str):
                    return value
            return None
        values = {value for value in hashes.values() if isinstance(value, str)}
        return values.pop() if len(values) == 1 else None


class _BadgeLocator(_DnsResolverBase):
    """Reads ``_ans-badge.{fqdn}`` to learn which log entry a name is filed under."""

    def __init__(self, owner_for: OwnerFn, query: DnsQuery, timeout: float) -> None:
        super().__init__(
            owner_for=owner_for,
            protocol=None,
            require_dnssec=False,
            nameservers=None,
            timeout=timeout,
            query=query,
            label="ans-badge",
            vantage=None,
        )

    async def locate(self, owner: str) -> tuple[tuple[str, str] | None, str]:
        answer, status, outcome = await self._ask(BADGE_TXT_PREFIX + owner, "TXT")
        if answer is None:
            return None, OUTCOME_NO_BADGE if status == "absent" else outcome
        found: set[tuple[str, str]] = set()
        for value in answer.txt:
            fields = parse_ans_txt(value)
            if fields.get("v", "").lower() != BADGE_TXT_VERSION:
                continue
            split = split_badge_url(fields.get("url", ""))
            if split is None:
                return None, OUTCOME_UNPARSEABLE
            found.add(split)
        if not found:
            return None, OUTCOME_NO_BADGE
        if len(found) > 1:
            return None, OUTCOME_AMBIGUOUS_RRSET
        return found.pop(), "present"
