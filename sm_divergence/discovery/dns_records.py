"""DNS as a discovery source — ``DnsSvcbResolver`` and ``DnsTxtResolver``.

A zone that publishes an agent's discovery records is one more source that can
be asked what it claims about a known subject. These two thin adapters map that
claim onto the ``sm-resolver`` ``Resolver`` contract, normalizing to
``(Status, RecordView)`` so a zone diffs against a registry with no
special-casing downstream:

- ``DnsSvcbResolver`` — SVCB ServiceMode rows (RFC 9460) at the agent's FQDN,
  one row per agent protocol;
- ``DnsTxtResolver`` — ``v=ans1`` TXT rows at ``_ans.{fqdn}``, one row per agent
  protocol.

**What a row contributes.** An SVCB row yields two addresses: the *service
endpoint* (``https://{target}:{port}{path}``) and the *descriptor* (the document
describing the agent, named outright or as an RFC 8615 well-known suffix).
``target`` selects which one becomes ``RecordView.endpoint``; the default is the
descriptor, the same thing a registry's terminal target names. A row that names
no descriptor contributes ``endpoint=None`` rather than silently substituting the
service address — that substitution would manufacture a divergence between two
honest sources. The descriptor digest, when published, becomes ``digest``.

**No ``did``.** A zone carries no agent-signed record, and a DID enters the view
only when verified.

**The agent-specific SvcParamKeys are configuration.** They have no assigned
code point, so ``SvcParamKeyMap`` names which key plays which role; the default
is the Private Use block 65400–65409.

**What these adapters never do.** No HTTP: the descriptor is not fetched and the
digest is not checked against its bytes. No TLSA. No enumeration: one instance
answers for the subjects it is asked about, one query chain each.

**Never a false ``absent``.** NXDOMAIN, an empty answer and an AliasMode row
whose TargetName is ``.`` are claims of absence. A timeout, a failing resolver, a
row this adapter cannot read, and — when ``require_dnssec`` is set — an answer
the recursive resolver did not authenticate are ``error``: no claim.

**Vantage.** A zone may answer differently by resolver. Run two instances with
the same ``label`` and different ``nameservers`` / ``vantage``; the kernel then
attributes the disagreement to ``source_equivocation``.

The network path is injectable (``query``); the default uses ``dnspython``,
installed with the ``dns`` extra and imported only when a default query is built.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

from sm_resolver import (
    OUTCOME_REFUSED,
    OUTCOME_TIMEOUT,
    OUTCOME_UNPARSEABLE,
    OUTCOME_UNREACHABLE,
    OUTCOME_UNVERIFIABLE,
    Status,
)

from .views import RecordView

Rcode = Literal["NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED", "OTHER"]
RdType = Literal["SVCB", "TXT"]
OwnerFn = Callable[[str], str]

# Equal-priority rows that reduce to different views: the zone gave two answers
# to one question, and choosing between them would be this adapter's claim, not
# the zone's. Namespaced, as a value outside the kernel's seeded vocabulary.
OUTCOME_AMBIGUOUS_RRSET = "ai.stellarminds.dns.ambiguous-rrset"

# SvcParamKeys with registered meanings (RFC 9460 section 14.3.2): mandatory,
# alpn, no-default-alpn, port, ipv4hint, ech, ipv6hint.
STANDARD_SVC_PARAM_KEYS = frozenset(range(7))

ANS_TXT_VERSION = "ans1"
ANS_TXT_PREFIX = "_ans."

_DEFAULT_PORT = 443
_MAX_NAME_LENGTH = 253
_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


@dataclass(frozen=True)
class SvcParamKeyMap:
    """Which SvcParamKey number plays which agent-discovery role.

    ``descriptor`` — absolute URI of the descriptor document.
    ``descriptor_digest`` — SHA-256 of that document.
    ``agent_protocol`` — the agent protocol token (``a2a``, ``mcp``, ``x-…``).
    ``well_known`` — an RFC 8615 suffix; the descriptor is then
    ``https://{fqdn}/.well-known/{suffix}``.
    ``path`` — the request path of the service endpoint; unset means ``/``.

    A role set to ``None`` is not read. Every key named here counts as
    understood when a row lists it under ``mandatory``.
    """

    descriptor: int | None = 65400
    descriptor_digest: int | None = 65401
    agent_protocol: int | None = 65402
    well_known: int | None = 65409
    path: int | None = None

    def known(self) -> frozenset[int]:
        roles = (self.descriptor, self.descriptor_digest, self.agent_protocol, self.well_known, self.path)
        return frozenset(key for key in roles if key is not None)


DEFAULT_KEY_MAP = SvcParamKeyMap()


@dataclass(frozen=True)
class SvcbRow:
    """One SVCB resource record, reduced to what the adapter reads.

    ``target`` is ``.`` or a hostname. ``params`` holds every key outside the
    registered set, decoded as text.
    """

    priority: int
    target: str = "."
    alpn: tuple[str, ...] = ()
    port: int | None = None
    mandatory: tuple[int, ...] = ()
    params: Mapping[int, str] = field(default_factory=dict)


@dataclass(frozen=True)
class DnsAnswer:
    """One response from the recursive resolver.

    ``svcb`` / ``txt`` are empty on NODATA. ``authenticated`` is the AD bit: the
    resolver validated the answer (or the denial) with DNSSEC. ``malformed`` is
    set when the response held a record that could not be read.
    """

    rcode: Rcode = "NOERROR"
    svcb: tuple[SvcbRow, ...] = ()
    txt: tuple[str, ...] = ()
    authenticated: bool = False
    malformed: bool = False


# The network seam: an absolute query name and a record type in, one answer out.
# Raising ``TimeoutError`` means no answer within the deadline; raising anything
# else means the transport failed.
DnsQuery = Callable[[str, RdType], Awaitable[DnsAnswer]]


def identity_owner(agent_id: str) -> str:
    """Default ``owner_for``: the watch id already *is* the agent's FQDN."""
    return agent_id


def normalize_owner(owner: str) -> str | None:
    """Reduce an owner name to the form that is queried, or ``None`` if unusable.

    Lowercased, IDNA-encoded, one trailing dot removed. A name with fewer than
    two labels is rejected: a bare id is not a DNS name, and querying it would
    turn an identity-correspondence gap into a false ``absent``.
    """
    text = owner.strip()
    if text.endswith("."):
        text = text[:-1]
    labels: list[str] = []
    for label in text.split("."):
        try:
            encoded = label.lower() if label.isascii() else label.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if not _LABEL.match(encoded):
            return None
        labels.append(encoded)
    if len(labels) < 2:
        return None
    name = ".".join(labels)
    return name if len(name) <= _MAX_NAME_LENGTH else None


def parse_ans_txt(text: str) -> dict[str, str]:
    """Split one TXT value into its ``key=value`` fields (keys lowercased).

    ``url`` is read to the end of the value, so a ``;`` inside the URL does not
    truncate it. Text without ``key=value`` shape yields an empty mapping.
    """
    fields: dict[str, str] = {}
    rest = text
    while rest:
        part, _, remainder = rest.partition(";")
        key, sep, value = part.strip().partition("=")
        key = key.strip().lower()
        if sep and key == "url":
            fields[key] = (value + (";" + remainder if remainder else "")).strip()
            break
        if sep and key:
            fields[key] = value.strip()
        rest = remainder
    return fields


def _view_key(view: RecordView) -> tuple[tuple[str, str | None], ...]:
    return tuple(sorted(view.comparable().items()))


class _DnsResolverBase:
    def __init__(
        self,
        *,
        owner_for: OwnerFn,
        protocol: str | None,
        require_dnssec: bool,
        nameservers: Sequence[str] | None,
        timeout: float,
        query: DnsQuery | None,
        label: str,
        vantage: str | None,
    ) -> None:
        self.owner_for = owner_for
        self.protocol = protocol.lower() if protocol is not None else None
        self.require_dnssec = require_dnssec
        self.timeout = timeout
        self._query: DnsQuery = query if query is not None else DnspythonQuery(nameservers, timeout=timeout)
        self._label = label
        self.vantage = vantage

    @property
    def label(self) -> str:
        return self._label

    def _owner(self, agent_id: str) -> str | None:
        try:
            return normalize_owner(self.owner_for(agent_id))
        except Exception:
            return None

    async def _ask(self, name: str, rdtype: RdType) -> tuple[DnsAnswer | None, Status, str]:
        """One query, classified. Returns the answer only when it carries a claim to read."""
        try:
            async with asyncio.timeout(self.timeout):
                answer = await self._query(name + ".", rdtype)
        except TimeoutError:
            return None, "error", OUTCOME_TIMEOUT
        except Exception:
            return None, "error", OUTCOME_UNREACHABLE
        if answer.rcode == "REFUSED":
            return None, "error", OUTCOME_REFUSED
        if answer.rcode not in ("NOERROR", "NXDOMAIN"):
            return None, "error", OUTCOME_UNREACHABLE
        if answer.malformed:
            return None, "error", OUTCOME_UNPARSEABLE
        # An unauthenticated denial is no more a claim than an unauthenticated
        # answer, so this precedes the absence checks.
        if self.require_dnssec and not answer.authenticated:
            return None, "error", OUTCOME_UNVERIFIABLE
        if answer.rcode == "NXDOMAIN":
            return None, "absent", "absent"
        return answer, "present", "present"

    async def resolve_with_outcome(self, agent_id: str) -> tuple[Status, RecordView | None, str]:
        raise NotImplementedError

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        status, view, _ = await self.resolve_with_outcome(agent_id)
        return status, view


class DnsSvcbResolver(_DnsResolverBase):
    """Resolve a canonical id through the SVCB rows at the agent's FQDN.

    ``owner_for`` maps the canonical watch id to that FQDN (identity
    correspondence is the caller's; default: the id already is the FQDN).
    ``protocol`` selects the row for one agent protocol; ``None`` takes the
    lowest-priority row. ``target`` chooses whether ``endpoint`` is the
    descriptor (default) or the service endpoint. ``key_map`` names the
    agent-specific SvcParamKeys. ``max_alias_hops`` bounds AliasMode chasing.
    ``require_dnssec`` turns an answer the recursive resolver did not
    authenticate into ``error``/``unverifiable``. ``nameservers`` picks the
    recursive resolvers for the default query (``None``: the system's);
    ``query`` replaces the network path entirely, for tests.
    """

    def __init__(
        self,
        *,
        owner_for: OwnerFn = identity_owner,
        protocol: str | None = None,
        target: Literal["descriptor", "service"] = "descriptor",
        key_map: SvcParamKeyMap = DEFAULT_KEY_MAP,
        max_alias_hops: int = 1,
        require_dnssec: bool = False,
        nameservers: Sequence[str] | None = None,
        timeout: float = 5.0,
        query: DnsQuery | None = None,
        label: str | None = None,
        vantage: str | None = None,
    ) -> None:
        super().__init__(
            owner_for=owner_for,
            protocol=protocol,
            require_dnssec=require_dnssec,
            nameservers=nameservers,
            timeout=timeout,
            query=query,
            label=label or "dns-svcb",
            vantage=vantage,
        )
        self.target = target
        self.key_map = key_map
        self.max_alias_hops = max(0, int(max_alias_hops))

    async def resolve_with_outcome(self, agent_id: str) -> tuple[Status, RecordView | None, str]:
        """Never raises. ``present``/``absent`` use their status as outcome."""
        owner = self._owner(agent_id)
        if owner is None:
            return "error", None, OUTCOME_UNPARSEABLE

        hops = 0
        while True:
            answer, status, outcome = await self._ask(owner, "SVCB")
            if answer is None:
                return status, None, outcome
            rows = answer.svcb
            if not rows:
                return "absent", None, "absent"
            aliases = [row for row in rows if row.priority == 0]
            if not aliases:
                break
            # RFC 9460 2.4.1: with an AliasMode row present, ServiceMode rows in
            # the same RRset are ignored.
            targets = {row.target if row.target == "." else normalize_owner(row.target) for row in aliases}
            if len(targets) > 1:
                return "error", None, OUTCOME_AMBIGUOUS_RRSET
            alias = targets.pop()
            if alias == ".":
                # RFC 9460 2.5.1: the service is not available or does not exist.
                return "absent", None, "absent"
            if alias is None or hops >= self.max_alias_hops:
                return "error", None, OUTCOME_UNPARSEABLE
            hops += 1
            owner = alias

        # RFC 9460 section 8: a row whose `mandatory` lists a key the client does
        # not implement is ignored. Rows that existed and were all unreadable are
        # not a claim of absence.
        understood = STANDARD_SVC_PARAM_KEYS | self.key_map.known()
        usable = [row for row in rows if all(key in understood for key in row.mandatory)]
        if not usable:
            return "error", None, OUTCOME_UNPARSEABLE

        if self.protocol is not None:
            usable = [row for row in usable if self._speaks(row, self.protocol)]
            if not usable:
                return "absent", None, "absent"

        best = min(row.priority for row in usable)
        views: list[RecordView] = []
        for row in usable:
            if row.priority != best:
                continue
            view = self._view(row, owner)
            if view is None:
                return "error", None, OUTCOME_UNPARSEABLE
            views.append(view)
        if len({_view_key(view) for view in views}) > 1:
            return "error", None, OUTCOME_AMBIGUOUS_RRSET
        return "present", views[0], "present"

    def _speaks(self, row: SvcbRow, protocol: str) -> bool:
        key = self.key_map.agent_protocol
        declared = row.params.get(key) if key is not None else None
        if declared is not None:
            return declared.strip().lower() == protocol
        return protocol in (alpn.lower() for alpn in row.alpn)

    def _view(self, row: SvcbRow, owner: str) -> RecordView | None:
        """Reduce one ServiceMode row to the discovery view; ``None`` if malformed."""
        keys = self.key_map
        host = owner if row.target == "." else normalize_owner(row.target)
        if host is None:
            return None
        path = "/"
        if keys.path is not None and keys.path in row.params:
            path = row.params[keys.path]
            if not path.startswith("/"):
                return None
        port = _DEFAULT_PORT if row.port is None else row.port
        authority = host if port == _DEFAULT_PORT else f"{host}:{port}"
        service = f"https://{authority}{path}"

        descriptor: str | None = None
        named = row.params.get(keys.descriptor) if keys.descriptor is not None else None
        suffix = row.params.get(keys.well_known) if keys.well_known is not None else None
        if named:
            descriptor = named
        elif suffix is not None:
            if not suffix or any(char in suffix for char in "/?#"):
                return None
            descriptor = f"https://{owner}/.well-known/{suffix}"

        digest = row.params.get(keys.descriptor_digest) if keys.descriptor_digest is not None else None
        return RecordView(
            endpoint=descriptor if self.target == "descriptor" else service,
            digest=digest or None,
        )


class DnsTxtResolver(_DnsResolverBase):
    """Resolve a canonical id through the ``v=ans1`` TXT rows at ``_ans.{fqdn}``.

    Each row is ``v=ans1; version=…; p={protocol}; mode=…; url={endpoint}``.
    ``protocol`` selects the row whose ``p`` matches; ``None`` accepts every row,
    so a name publishing more than one protocol needs ``protocol`` set. Other TXT
    data at the name is ignored. The remaining arguments are as for
    ``DnsSvcbResolver``.
    """

    def __init__(
        self,
        *,
        owner_for: OwnerFn = identity_owner,
        protocol: str | None = None,
        require_dnssec: bool = False,
        nameservers: Sequence[str] | None = None,
        timeout: float = 5.0,
        query: DnsQuery | None = None,
        label: str | None = None,
        vantage: str | None = None,
    ) -> None:
        super().__init__(
            owner_for=owner_for,
            protocol=protocol,
            require_dnssec=require_dnssec,
            nameservers=nameservers,
            timeout=timeout,
            query=query,
            label=label or "dns-txt",
            vantage=vantage,
        )

    async def resolve_with_outcome(self, agent_id: str) -> tuple[Status, RecordView | None, str]:
        """Never raises. ``present``/``absent`` use their status as outcome."""
        owner = self._owner(agent_id)
        if owner is None:
            return "error", None, OUTCOME_UNPARSEABLE
        answer, status, outcome = await self._ask(ANS_TXT_PREFIX + owner, "TXT")
        if answer is None:
            return status, None, outcome

        rows = [fields for fields in map(parse_ans_txt, answer.txt) if fields.get("v") == ANS_TXT_VERSION]
        if self.protocol is not None:
            rows = [fields for fields in rows if fields.get("p", "").lower() == self.protocol]
        if not rows:
            return "absent", None, "absent"

        views: list[RecordView] = []
        for fields in rows:
            url = fields.get("url", "")
            try:
                parts = urlsplit(url)
            except ValueError:
                return "error", None, OUTCOME_UNPARSEABLE
            if parts.scheme.lower() not in ("http", "https") or not parts.netloc:
                return "error", None, OUTCOME_UNPARSEABLE
            views.append(RecordView(endpoint=url))
        if len({_view_key(view) for view in views}) > 1:
            return "error", None, OUTCOME_AMBIGUOUS_RRSET
        return "present", views[0], "present"


# --- the default network path (dnspython) -------------------------------------


def _require_dnspython() -> None:
    try:
        import dns.asyncresolver  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError("DNS discovery needs dnspython: install 'sm-divergence[dns]'") from exc


def svcb_row_from_rdata(rdata: Any) -> SvcbRow:
    """Reduce a dnspython SVCB rdata to an ``SvcbRow``. Raises on an unreadable value."""
    alpn: tuple[str, ...] = ()
    port: int | None = None
    mandatory: tuple[int, ...] = ()
    params: dict[int, str] = {}
    for key, value in rdata.params.items():
        number = int(key)
        if number == 0:
            mandatory = tuple(int(listed) for listed in value.keys)
        elif number == 1:
            alpn = tuple(bytes(ident).decode("ascii") for ident in value.ids)
        elif number == 3:
            port = int(value.port)
        elif number in STANDARD_SVC_PARAM_KEYS:
            continue
        else:
            raw = getattr(value, "value", b"") if value is not None else b""
            params[number] = bytes(raw).decode("utf-8")
    return SvcbRow(
        priority=int(rdata.priority),
        target=rdata.target.to_text(),
        alpn=alpn,
        port=port,
        mandatory=mandatory,
        params=params,
    )


def txt_row_from_rdata(rdata: Any) -> str:
    """Join the character-strings of a dnspython TXT rdata into one value."""
    return b"".join(bytes(part) for part in rdata.strings).decode("utf-8")


def svcb_rows_from_text(*records: str) -> tuple[SvcbRow, ...]:
    """Parse SVCB RDATA in presentation format (zone-file text). Raises if unparseable."""
    _require_dnspython()
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype

    return tuple(
        svcb_row_from_rdata(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SVCB, text)) for text in records
    )


def txt_rows_from_text(*records: str) -> tuple[str, ...]:
    """Parse TXT RDATA in presentation format (zone-file text). Raises if unparseable."""
    _require_dnspython()
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype

    return tuple(
        txt_row_from_rdata(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, text)) for text in records
    )


class DnspythonQuery:
    """The default ``DnsQuery``: a recursive lookup through ``dnspython``.

    ``nameservers`` are the recursive resolvers to ask, on ``port``; ``None``
    reads the system configuration. The query sets the AD bit, so a validating resolver
    reports whether it authenticated the answer. That report is only as
    trustworthy as the path to the resolver: ``require_dnssec`` is meaningful
    against a validating resolver reached over a trusted channel.

    The search list is never applied, and CNAMEs are followed by the resolver.
    """

    def __init__(self, nameservers: Sequence[str] | None = None, *, port: int = 53, timeout: float = 5.0) -> None:
        _require_dnspython()
        import dns.asyncresolver
        import dns.flags

        self._resolver = dns.asyncresolver.Resolver(configure=nameservers is None)
        if nameservers is not None:
            self._resolver.nameservers = list(nameservers)
        self._resolver.port = port
        self._resolver.flags = dns.flags.RD | dns.flags.AD
        self._timeout = timeout

    async def __call__(self, name: str, rdtype: RdType) -> DnsAnswer:
        import dns.exception
        import dns.flags
        import dns.rcode
        import dns.resolver

        try:
            answer = await self._resolver.resolve(
                name, rdtype, raise_on_no_answer=False, search=False, lifetime=self._timeout
            )
        except dns.resolver.NXDOMAIN as exc:
            responses = list(exc.kwargs.get("responses", {}).values())
            authenticated = bool(responses) and all(bool(r.flags & dns.flags.AD) for r in responses)
            return DnsAnswer(rcode="NXDOMAIN", authenticated=authenticated)
        except dns.resolver.NoNameservers as exc:
            rcodes = {
                error[4].rcode() for error in exc.kwargs.get("errors", []) if len(error) > 4 and error[4] is not None
            }
            return DnsAnswer(rcode="REFUSED" if rcodes == {dns.rcode.REFUSED} else "SERVFAIL")
        except dns.exception.Timeout as exc:
            raise TimeoutError from exc
        except dns.exception.DNSException:
            return DnsAnswer(rcode="OTHER")

        authenticated = bool(answer.response.flags & dns.flags.AD)
        rdatas = list(answer.rrset) if answer.rrset is not None else []
        try:
            if rdtype == "SVCB":
                return DnsAnswer(svcb=tuple(svcb_row_from_rdata(r) for r in rdatas), authenticated=authenticated)
            return DnsAnswer(txt=tuple(txt_row_from_rdata(r) for r in rdatas), authenticated=authenticated)
        except Exception:
            return DnsAnswer(malformed=True, authenticated=authenticated)
