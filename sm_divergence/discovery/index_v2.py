"""NandaIndexV2Resolver — a THIN adapter for the NANDA Index v2 two-hop resolve.

This is the shape the whole kernel/layer seam exists to enable: a small file
that maps one registry's protocol onto the ``sm-resolver`` ``Resolver`` contract,
with no machinery of its own. The NANDA Index is a *pointer* layer, so resolving
one agent is two hops:

    1. GET {index_url}/api/v1/resolve?locator={locator}
         → { "registry_url": "...", "identifier": "..." }
    2. GET {registry_url}{record_path with identifier}
         → the agent record (e.g. an ai-catalog CatalogEntry)

Both hops are performed here and normalized to ``(Status, RecordView)`` — so a
NANDA-Index claim diffs against a NEST claim with no special-casing downstream.

**Identity correspondence** is the caller's to define: the same agent is a bare
id on a NEST-style registry and a URN locator on the Index. ``locator_for`` maps
the canonical id to the Index's locator (default: the id already *is* the
locator). See WHITEPAPER §6.
"""

from __future__ import annotations

from collections.abc import Callable

import httpx
from sm_resolver import Status

from .client import RecordAdapter, default_adapter, looks_absent
from .views import RecordView

LocatorFn = Callable[[str], str]

DEFAULT_RESOLVE_PATH = "/api/v1/resolve"
DEFAULT_RECORD_PATH = "/agents/{id}"


def identity_locator(agent_id: str) -> str:
    """Default ``locator_for``: the watch id already *is* the Index locator."""
    return agent_id


class NandaIndexV2Resolver:
    """Resolve a canonical id through a NANDA Index v2 (resolve → registry → record)."""

    def __init__(
        self,
        index_url: str,
        *,
        locator_for: LocatorFn = identity_locator,
        resolve_path: str = DEFAULT_RESOLVE_PATH,
        record_path: str = DEFAULT_RECORD_PATH,
        adapter: RecordAdapter = default_adapter,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
    ) -> None:
        self.index_url = index_url.rstrip("/")
        self.locator_for = locator_for
        self.resolve_path = resolve_path
        self.record_path = record_path
        self.adapter = adapter
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.index_url

    @property
    def label(self) -> str:
        return self._label

    async def _hop1(self, client: httpx.AsyncClient, locator: str) -> tuple[Status, tuple[str, str] | None]:
        """Resolve the locator to ``(registry_url, identifier)``, or a claim state."""
        try:
            resp = await client.get(
                f"{self.index_url}{self.resolve_path}", params={"locator": locator}, timeout=self.timeout
            )
        except Exception:
            return "error", None
        if resp.status_code == 404:
            return "absent", None
        if resp.status_code != 200:
            return "error", None
        try:
            doc = resp.json()
        except Exception:
            return "error", None
        if not isinstance(doc, dict):
            return "error", None
        if looks_absent(doc):
            return "absent", None
        registry_url = doc.get("registry_url")
        identifier = doc.get("identifier")
        if not isinstance(registry_url, str) or not registry_url:
            return "error", None
        if not isinstance(identifier, str) or not identifier:
            return "error", None
        return "present", (registry_url.rstrip("/"), identifier)

    async def _hop2(
        self, client: httpx.AsyncClient, registry_url: str, identifier: str
    ) -> tuple[Status, RecordView | None]:
        """Fetch the pointed-to record and map it to a RecordView."""
        url = registry_url + self.record_path.replace("{id}", identifier)
        try:
            resp = await client.get(url, timeout=self.timeout)
        except Exception:
            return "error", None
        if resp.status_code == 404:
            return "absent", None
        if resp.status_code != 200:
            return "error", None
        try:
            doc = resp.json()
        except Exception:
            return "error", None
        if not isinstance(doc, dict):
            return "error", None
        if looks_absent(doc):
            return "absent", None
        try:
            return "present", self.adapter(doc)
        except Exception:
            return "error", None

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        locator = self.locator_for(agent_id)
        async with httpx.AsyncClient(transport=self._transport) as client:
            status, pointer = await self._hop1(client, locator)
            if status != "present" or pointer is None:
                return status, None
            registry_url, identifier = pointer
            return await self._hop2(client, registry_url, identifier)
