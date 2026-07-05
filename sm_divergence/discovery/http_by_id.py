"""HttpByIdResolver — the ``GET {base}/api/agents/{id}`` registry shape (e.g. NEST).

The reference discovery resolver: a thin adapter mapping a single-hop by-id HTTP
registry onto the core ``Resolver`` protocol.
"""

from __future__ import annotations

import httpx
from sm_resolver import Status

from .client import DEFAULT_PATH, RecordAdapter, default_adapter, fetch_view
from .views import RecordView


class HttpByIdResolver:
    """A registry that serves ``GET {base}/api/agents/{id}``.

    The record path and the record→view mapping are injectable, so this also
    covers any single-hop by-id HTTP registry. ``transport`` is an injectable
    httpx transport for tests; ``None`` uses the real network.
    """

    def __init__(
        self,
        base_url: str,
        *,
        adapter: RecordAdapter = default_adapter,
        path: str = DEFAULT_PATH,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.adapter = adapter
        self.path = path
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.base_url

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        async with httpx.AsyncClient(transport=self._transport) as client:
            return await fetch_view(
                client,
                self.base_url,
                agent_id,
                adapter=self.adapter,
                path=self.path,
                timeout=self.timeout,
            )
