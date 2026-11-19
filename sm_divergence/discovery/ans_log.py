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
the badge TXT row at the FQDN (``v=ans-badge1`` at ``_ans-badge.{fqdn}``, or
``v=ra-badge1`` at ``_ra-badge.{fqdn}``), which names the log and the entry. A badge row that names a log other than the one configured is
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

**Verified or not.** Without ``root_keys`` the badge is read as served: the
view is the log's unsigned claim, compared like any registry's ``endpoint``.
With ``root_keys`` — the log's verification keys, pinned by the caller — nothing
unsigned is used. The event is taken from the log's receipt, whose signature and
inclusion proof must verify (``log_receipt.verify_receipt``) and whose event
must be the entry asked for; the status is taken from the log's status token,
which must verify, name that entry and be current. Any failure is
``error``/``unverifiable``, including a log that serves no status token: a
sealed event with no proven status is not a claim about the present.

A verified claim shows the log's key signed it. It does not show the receipt's
root to be the log's current one, nor that no later event supersedes the one
sealed; and keys fetched from the log being read prove only that the log is
self-consistent. The view carries no ``did`` either way.

Needs the ``dns`` extra (attested records are zone-file text), and the ``cose``
extra when ``root_keys`` is given.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
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
from .log_receipt import ReceiptError, parse_root_keys, verify_receipt, verify_status_token
from .views import RecordView, normalize_endpoint

AgentIdFn = Callable[[str], str]

BADGE_PATH = "/v1/agents/{id}"
RECEIPT_PATH = "/v1/agents/{id}/receipt"
STATUS_TOKEN_PATH = "/v1/agents/{id}/status-token"
RECEIPT_MEDIA_TYPE = "application/scitt-receipt+cose"
STATUS_TOKEN_MEDIA_TYPE = "application/ans-status-token+cbor"
# The badge row has been published under two owner labels, each with its own
# version tag. Both are read, in this order.
BADGE_TXT_ROWS: tuple[tuple[str, str], ...] = (("_ans-badge.", "ans-badge1"), ("_ra-badge.", "ra-badge1"))

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


def _attested_records(records: Any) -> list[tuple[str, str, str]]:
    """The attested DNS records as ``(name, type, data)``. Raises if unreadable.

    Two shapes are published: a list of ``{name, type, data}`` objects, and a
    map from owner name to value, whose entries are TXT records.
    """
    if records is None:
        return []
    if isinstance(records, dict):
        return [(str(name), "TXT", str(value)) for name, value in records.items()]
    if isinstance(records, list):
        return [(str(r["name"]), str(r["type"]).upper(), str(r["data"])) for r in records]
    raise ValueError("dnsRecordsProvisioned is neither a list nor a map")


class AnsLogResolver:
    """Resolve a canonical id through one transparency log's public badge route.

    ``log_url`` is the log's base URL. ``agent_id_for`` maps the canonical watch
    id to the log's ``agentId``; when it is ``None`` the entry is located through
    the badge TXT row at the FQDN ``owner_for`` returns. ``protocol``,
    ``target`` and ``key_map`` are as for ``DnsSvcbResolver`` and are applied to
    the records the log attests. ``root_keys`` turns on verification: the
    log's keys, as ``log_receipt.parse_root_keys`` accepts them. ``clock`` and
    ``leeway`` govern the status token's validity window. ``badge_query`` replaces the DNS lookup of the
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
        root_keys: Mapping[str, Any] | str | Iterable[str] | None = None,
        badge_path: str = BADGE_PATH,
        receipt_path: str = RECEIPT_PATH,
        status_token_path: str = STATUS_TOKEN_PATH,
        clock: Callable[[], float] = time.time,
        leeway: float = 60.0,
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
        self.receipt_path = receipt_path
        self.status_token_path = status_token_path
        self.clock = clock
        self.leeway = leeway
        # Unusable keys are a configuration error, raised here rather than
        # reported as a claim on every resolve.
        self._keys: Mapping[str, Any] | None = None
        if root_keys is not None:
            self._keys = root_keys if isinstance(root_keys, Mapping) else parse_root_keys(root_keys)
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
                if self._keys is not None:
                    return await self._verified_claim(client, entry, expected_host, self._keys)
                resp, status, outcome = await self._get(client, self.badge_path, entry, "application/json")
                if resp is None:
                    return status, None, outcome
                badge = resp.json()
                if not isinstance(badge, dict):
                    return "error", None, OUTCOME_UNPARSEABLE
                return self._claim(badge.get("status"), badge["payload"]["producer"]["event"], expected_host)
        except Exception:
            # An answer this adapter cannot read is not a claim of absence.
            return "error", None, OUTCOME_UNPARSEABLE

    async def _get(
        self, client: httpx.AsyncClient, path: str, entry: str, accept: str
    ) -> tuple[httpx.Response | None, Status, str]:
        """One GET against the log, classified. The response is returned only on ``200``."""
        try:
            resp = await client.get(
                self.log_url + path.replace("{id}", entry), headers={"Accept": accept}, timeout=self.timeout
            )
        except httpx.TimeoutException:
            return None, "error", OUTCOME_TIMEOUT
        except Exception:
            return None, "error", OUTCOME_UNREACHABLE
        if resp.status_code == 404:
            return None, "absent", "absent"
        if resp.status_code in (401, 403):
            return None, "error", OUTCOME_REFUSED
        if resp.status_code != 200:
            return None, "error", OUTCOME_UNREACHABLE
        return resp, "present", "present"

    async def _verified_claim(
        self, client: httpx.AsyncClient, entry: str, expected_host: str | None, keys: Mapping[str, Any]
    ) -> tuple[Status, RecordView | None, str]:
        """The claim read from signed artifacts only: the receipt and the status token."""
        resp, status, outcome = await self._get(client, self.receipt_path, entry, RECEIPT_MEDIA_TYPE)
        if resp is None:
            return status, None, outcome
        try:
            receipt = verify_receipt(resp.content, keys)
        except ReceiptError:
            return "error", None, OUTCOME_UNVERIFIABLE
        event = json.loads(receipt.payload)["payload"]["producer"]["event"]
        # A valid receipt for another agent's event is not this agent's record.
        if str(event.get("ansId")) != entry:
            return "error", None, OUTCOME_UNVERIFIABLE

        resp, status, outcome = await self._get(client, self.status_token_path, entry, STATUS_TOKEN_MEDIA_TYPE)
        if resp is None:
            # The sealed event is proven but its current status is not.
            return "error", None, OUTCOME_UNVERIFIABLE if status == "absent" else outcome
        try:
            token = verify_status_token(resp.content, keys, now=self.clock(), leeway=self.leeway)
        except ReceiptError:
            return "error", None, OUTCOME_UNVERIFIABLE
        if token.agent_id != entry:
            return "error", None, OUTCOME_UNVERIFIABLE
        return self._claim(token.status, event, expected_host)

    def _claim(self, status: Any, event: Any, expected_host: str | None) -> tuple[Status, RecordView | None, str]:
        if status == "REVOKED":
            return "error", None, OUTCOME_REVOKED
        if status == "EXPIRED":
            return "error", None, OUTCOME_EXPIRED
        if status not in _LIVE_STATUSES:
            return "error", None, OUTCOME_UNPARSEABLE

        host = normalize_owner(event["agent"]["host"])
        if host is None:
            return "error", None, OUTCOME_UNPARSEABLE
        if expected_host is not None and host != expected_host:
            return "error", None, OUTCOME_UNVERIFIABLE

        attestations = event.get("attestations") or {}
        svcb: list[str] = []
        txt: list[str] = []
        for name, rdtype, data in _attested_records(attestations.get("dnsRecordsProvisioned")):
            owner = normalize_owner(name)
            if rdtype == "SVCB" and owner == host:
                svcb.append(data)
            elif rdtype == "TXT" and owner == ANS_TXT_PREFIX + host:
                txt.append(_zone_text(data, rdtype))

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
        found: set[tuple[str, str]] = set()
        for prefix, version in BADGE_TXT_ROWS:
            answer, status, outcome = await self._ask(prefix + owner, "TXT")
            if answer is None:
                if status == "absent":
                    continue
                return None, outcome
            for value in answer.txt:
                fields = parse_ans_txt(value)
                if fields.get("v", "").lower() != version:
                    continue
                split = split_badge_url(fields.get("url", ""))
                if split is None:
                    return None, OUTCOME_UNPARSEABLE
                found.add(split)
            if found:
                break
        if not found:
            return None, OUTCOME_NO_BADGE
        if len(found) > 1:
            return None, OUTCOME_AMBIGUOUS_RRSET
        return found.pop(), "present"
