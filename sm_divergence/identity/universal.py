"""UniversalResolverResolver — resolve any DID method via a DIF Universal
Resolver endpoint (``GET {base}/1.0/identifiers/{did}``).

One adapter covers every method a Universal Resolver driver supports, so a
Universal Resolver's answer can be corroborated against a direct ``did:web``
fetch or the root ``did:key`` — catching a resolver (or a driver) that returns a
different key than the source of truth.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx
from sm_resolver import Status

from .didweb import key_from_did_document
from .views import DidFor, DidView, identity_did

DEFAULT_RESOLVE_PATH = "/1.0/identifiers/{did}"


class UniversalResolverResolver:
    """Resolve a canonical agent id's DID through a Universal Resolver endpoint.

    The endpoint returns a DID resolution result (``{"didDocument": {...}, …}``);
    the key is extracted from the document exactly as for ``did:web``.
    """

    def __init__(
        self,
        base_url: str,
        *,
        did_for: DidFor = identity_did,
        resolve_path: str = DEFAULT_RESOLVE_PATH,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.did_for = did_for
        self.resolve_path = resolve_path
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.base_url

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, DidView | None]:
        did = self.did_for(agent_id)
        url = self.base_url + self.resolve_path.replace("{did}", quote(did, safe=""))
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
            body = resp.json()
        except Exception:
            return "error", None
        if not isinstance(body, dict):
            return "error", None
        doc: Any = body.get("didDocument")
        if not isinstance(doc, dict):
            doc = body  # some endpoints return the document directly
        key = key_from_did_document(doc)
        if key is None:
            return "error", None
        return "present", DidView(key=key)
