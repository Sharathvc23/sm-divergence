"""The self-description as its own corroborated layer — dogfooding the mechanism.

A self-description is only as trustworthy as its distribution. If a consumer
takes the bundle from one of the sources under test, that hostile source controls
whether and which version you see — omission and replay apply to the description
itself. So fetch it from *every* source and corroborate it like everything else:
a source serving a stale, forged, or missing description becomes an ordinary
finding rather than a silent poisoning of correspondence.

The reconcile is ``seq``-aware (supersession — highest wins), which the generic
field diff intentionally cannot express, so this layer resolves via the kernel
pattern but reduces with ``reconcile_descriptions``. It yields three findings and
the canonical description:

- ``agent_equivocation`` — two VALID descriptions at the same top ``seq`` with
  different content: the agent's key signed two conflicting statements (key
  compromise or a lying agent). This is the system's first equivocation
  detection. Correspondence FAILS CLOSED (no canonical) when it fires.
- ``omission`` — some sources serve a description, others positively don't.
- ``stale_description`` — a source is behind the top ``seq`` (replay / lag).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

import httpx
from sm_resolver import Finding, Status

from .selfdesc import SelfDescription, verify_self_description
from .views import DidFor, identity_did


@dataclass(frozen=True)
class DescriptionReconciliation:
    """The outcome of corroborating an agent's self-description across sources.

    ``canonical`` is the surviving highest-``seq`` description that MAY drive
    correspondence — or None when the sources equivocate (fail closed). ``findings``
    are the divergences observed while getting there.
    """

    canonical: SelfDescription | None
    findings: list[Finding] = field(default_factory=list)


def reconcile_descriptions(
    agent_id: str,
    views: Mapping[str, SelfDescription | None],
) -> DescriptionReconciliation:
    """Reconcile the per-source descriptions for one agent (``seq``-aware).

    ``views[source]`` is a verified ``SelfDescription`` (present), ``None``
    (source positively served none), or the source simply absent from the map
    (unreachable / unverifiable — no claim). Never raises.
    """
    present = {src: sd for src, sd in views.items() if sd is not None}
    absent = sorted(src for src, sd in views.items() if sd is None)
    if not present:
        return DescriptionReconciliation(None, [])

    findings: list[Finding] = []
    max_seq = max(sd.seq for sd in present.values())
    top = {src: sd for src, sd in present.items() if sd.seq == max_seq}

    canonical: SelfDescription | None
    if len({sd.content_key() for sd in top.values()}) > 1:
        # The did:key signed two different things at the same seq → equivocation.
        findings.append(Finding("agent_equivocation", agent_id, {"seq": max_seq, "sources": sorted(top)}))
        canonical = None  # fail closed — the identity's correspondence is untrustworthy
    else:
        canonical = next(iter(top.values()))

    if present and absent:
        findings.append(Finding("omission", agent_id, {"present_on": sorted(present), "missing_from": absent}))

    stale = sorted(src for src, sd in present.items() if sd.seq < max_seq)
    if stale:
        findings.append(Finding("stale_description", agent_id, {"stale_on": stale, "current_seq": max_seq}))

    return DescriptionReconciliation(canonical, findings)


class HttpDescriptionResolver:
    """Fetch + verify an agent's self-description from one source over HTTP.

    Returns ``present`` with the verified ``SelfDescription``, ``absent`` on a
    404, and ``error`` otherwise (unreachable, non-200, or a served bundle that
    does not verify — an unverifiable description is no claim, never trusted).
    """

    def __init__(
        self,
        base_url: str,
        *,
        path: str = "/.well-known/agent-self-description.json",
        locator_for: DidFor = identity_did,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.path = path
        self.locator_for = locator_for
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.base_url

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, SelfDescription | None]:
        url = self.base_url + self.path.replace("{id}", self.locator_for(agent_id))
        try:
            async with httpx.AsyncClient(transport=self._transport) as client:
                resp = await client.get(url, timeout=self.timeout)
        except Exception:
            return "error", None
        if resp.status_code == 404:
            return "absent", None
        if resp.status_code != 200:
            return "error", None
        try:
            bundle = resp.json()
        except Exception:
            return "error", None
        sd = verify_self_description(bundle)
        if sd is None:
            return "error", None  # served but unverifiable — no claim
        return "present", sd


async def corroborate_descriptions(
    resolvers: Iterable[HttpDescriptionResolver],
    agent_ids: Iterable[str],
) -> dict[str, DescriptionReconciliation]:
    """Fetch each agent's description from every source and reconcile. Sources are
    deduped by ``label``; an ``error`` (no-claim) source is excluded. Returns a
    ``{agent_id: DescriptionReconciliation}`` map. Never raises."""
    deduped: list[HttpDescriptionResolver] = []
    seen: set[str] = set()
    for r in resolvers:
        if r.label in seen:
            continue
        seen.add(r.label)
        deduped.append(r)

    result: dict[str, DescriptionReconciliation] = {}
    for aid in sorted(set(agent_ids)):
        views: dict[str, SelfDescription | None] = {}
        for r in deduped:
            try:
                status, sd = await r.resolve(aid)
            except Exception:
                status, sd = "error", None
            if status == "error":
                continue
            views[r.label] = sd
        result[aid] = reconcile_descriptions(aid, views)
    return result
