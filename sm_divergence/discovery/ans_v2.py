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

Split-horizon ANS (an ANS-3 DNS zone that answers differently by vantage) is
caught by running two instances with the same ``label`` and different
``vantage`` / ``transport`` — the kernel then attributes the disagreement to
``source_equivocation`` rather than cross-source divergence.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
from sm_resolver import Status

from .client import RecordAdapter, default_adapter, fetch_view
from .views import RecordView

AnsNameFn = Callable[[str], str]

DEFAULT_RECORD_PATH = "/ans/agents/{id}"


def identity_ansname(agent_id: str) -> str:
    """Default ``ansname_for``: the watch id already *is* the ANS ``agentId``."""
    return agent_id


class AnsV2Resolver:
    """Resolve a canonical id through an Agent Name Service instance (one hop)."""

    def __init__(
        self,
        ans_url: str,
        *,
        ansname_for: AnsNameFn = identity_ansname,
        record_path: str = DEFAULT_RECORD_PATH,
        adapter: RecordAdapter = default_adapter,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
        vantage: str | None = None,
    ) -> None:
        self.ans_url = ans_url.rstrip("/")
        self.ansname_for = ansname_for
        self.record_path = record_path
        self.adapter = adapter
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.ans_url
        self.vantage = vantage

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        ans_id = self.ansname_for(agent_id)
        async with httpx.AsyncClient(transport=self._transport) as client:
            return await fetch_view(
                client,
                self.ans_url,
                ans_id,
                adapter=self.adapter,
                path=self.record_path,
                timeout=self.timeout,
            )
