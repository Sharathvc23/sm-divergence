"""AnsV2Resolver — a THIN adapter for Agent Name Service (ANS) resolve.

ANS is itself the registry: an agent resolves in ONE hop,

    GET {ans_url}/ans/agents/{agentId}  →  the agent record

(contrast ``NandaIndexV2Resolver``'s TWO hops, where the Index is only a pointer
to a registry). This resolver maps that one hop onto the ``sm-resolver``
``Resolver`` contract, normalizing to ``(Status, RecordView)`` — so an ANS claim
diffs against a NANDA-Index or NEST claim with no special-casing downstream.

**Identity correspondence** is the caller's to define: the same agent may be a
bare id on a NEST-style registry, a URN locator on the Index, and an *ANSName*
on ANS. ``ansname_for`` maps the canonical watch id to the ANS ``agentId``
(default: the id already *is* the agentId).

**The DID enters the view only when VERIFIED.** ANS binds identity in the ANS-2
Identity Certificate and seals lifecycle events in the ANS-4 transparency log;
verifying that is the job of the injected ``adapter`` (a ``RecordAdapter``
closure), so this resolver never learns ANS's certificate format and the core
diff never sees it. The default adapter contributes ``endpoint`` only —
endpoint/omission divergence need no crypto, and one unverifiable cert is not a
disagreement between two authorities. Supply a cert-verifying ``adapter`` (the
ANS analogue of :func:`sm_divergence.discovery.attestation.signed_record_adapter`)
to bring a verified ``did`` into the comparison.

**What a ``404`` means depends on the route.** Where the by-id route requires
a credential and answers ``404`` both for an agent that does not exist and for
one the caller may not see, a ``404`` is not a claim of absence. So a ``404`` is
``error`` — no claim — by default, and never a false ``absent``. Pass
``not_found_is_absent=True`` only on a route whose ``404`` can mean nothing but
"this agent does not exist". A sweep by a third party should read the public log
instead (``AnsLogResolver``), which needs no credential and whose ``404`` does
mean absent.

**The record lists ``endpoints[]``.** The default adapter, ``ans_agent_adapter``,
reads that shape: ``protocol`` selects the entry and ``target`` chooses whether
``endpoint`` is the descriptor (``metaDataUrl``, with ``metaDataHash`` as
``digest``) or the service endpoint (``agentUrl``). A record with no
``endpoints`` list falls back to a top-level ``endpoint``.

Split-horizon ANS (an ANS-3 DNS zone that answers differently by vantage) is
caught by running two instances with the same ``label`` and different
``vantage`` / ``transport`` — the kernel then attributes the disagreement to
``source_equivocation`` rather than cross-source divergence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Literal

import httpx
from sm_resolver import Status

from .client import RecordAdapter, default_adapter, fetch_view
from .views import RecordView

AnsNameFn = Callable[[str], str]


def ans_agent_adapter(
    *, protocol: str | None = None, target: Literal["descriptor", "service"] = "descriptor"
) -> RecordAdapter:
    """A ``RecordAdapter`` for an agent record that lists ``endpoints[]``.

    Each entry carries ``protocol``, ``agentUrl`` (the service endpoint) and,
    optionally, ``metaDataUrl`` with ``metaDataHash`` (the descriptor and its
    digest). ``protocol`` selects the entry; ``target`` chooses which address
    becomes ``endpoint``, as for ``DnsSvcbResolver``, so the record compares
    with what the agent's zone publishes. An entry with no descriptor
    contributes ``endpoint=None`` under ``target="descriptor"``.

    Entries that reduce to different views raise, which the resolver reports as
    ``error``: with several protocols registered, ``protocol`` must be set. A
    record with no ``endpoints`` list falls back to a top-level ``endpoint``.
    """
    wanted = protocol.lower() if protocol is not None else None

    def adapter(record: dict[str, Any]) -> RecordView:
        endpoints = record.get("endpoints")
        if not isinstance(endpoints, list):
            return default_adapter(record)
        views: dict[tuple[tuple[str, str | None], ...], RecordView] = {}
        for entry in endpoints:
            if not isinstance(entry, dict):
                raise ValueError("endpoints[] entry is not an object")
            if wanted is not None and str(entry.get("protocol", "")).lower() != wanted:
                continue
            address = entry.get("metaDataUrl") if target == "descriptor" else entry.get("agentUrl")
            digest = entry.get("metaDataHash")
            view = RecordView(
                endpoint=address if isinstance(address, str) and address else None,
                digest=digest if isinstance(digest, str) and digest else None,
            )
            views[tuple(sorted(view.comparable().items()))] = view
        if len(views) > 1:
            raise ValueError("endpoints[] entries disagree; set protocol")
        return next(iter(views.values())) if views else RecordView()

    return adapter


DEFAULT_RECORD_PATH = "/ans/agents/{id}"


def identity_ansname(agent_id: str) -> str:
    """Default ``ansname_for``: the watch id already *is* the ANS ``agentId``."""
    return agent_id


class AnsV2Resolver:
    """Resolve a canonical id through an Agent Name Service instance (one hop).

    ``adapter`` maps the record to the view; by default it is
    ``ans_agent_adapter(protocol=protocol, target=target)``, which reads the
    record's ``endpoints[]`` list and falls back to a top-level ``endpoint``.
    ``not_found_is_absent`` says what a ``404`` means on this route: ``False``
    (the default) makes it ``error`` — no claim; pass ``True`` only where a
    ``404`` can mean nothing but "this agent does not exist".
    """

    def __init__(
        self,
        ans_url: str,
        *,
        ansname_for: AnsNameFn = identity_ansname,
        record_path: str = DEFAULT_RECORD_PATH,
        adapter: RecordAdapter | None = None,
        protocol: str | None = None,
        target: Literal["descriptor", "service"] = "descriptor",
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
        vantage: str | None = None,
        not_found_is_absent: bool = False,
    ) -> None:
        self.not_found_is_absent = not_found_is_absent
        self.ans_url = ans_url.rstrip("/")
        self.ansname_for = ansname_for
        self.record_path = record_path
        self.adapter = adapter if adapter is not None else ans_agent_adapter(protocol=protocol, target=target)
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.ans_url
        self.vantage = vantage

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        """Never raises."""
        try:
            ans_id = self.ansname_for(agent_id)
        except Exception:
            return "error", None
        async with httpx.AsyncClient(transport=self._transport) as client:
            return await fetch_view(
                client,
                self.ans_url,
                ans_id,
                adapter=self.adapter,
                path=self.record_path,
                timeout=self.timeout,
                not_found="absent" if self.not_found_is_absent else "error",
            )
