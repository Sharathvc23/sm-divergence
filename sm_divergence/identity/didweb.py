"""DidWebResolver — resolve a ``did:web`` by fetching its DID document.

``did:web`` grounds identity in DNS + HTTPS: the key lives in a document the
domain serves. That makes it exactly the method a corroboration layer should
watch — a hijacked domain, a stale mirror, or a lying host serves a document
whose key differs from the agent's root ``did:key``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
from sm_resolver import Status

from .views import DidFor, DidView, identity_did


def did_web_url(did: str) -> str | None:
    """The HTTPS location of a ``did:web`` document, per the did:web method, or
    None if the string is not a ``did:web``.

    ``did:web:example.com``            → ``https://example.com/.well-known/did.json``
    ``did:web:example.com:a:b``        → ``https://example.com/a/b/did.json``
    ``did:web:example.com%3A3000``     → ``https://example.com:3000/.well-known/did.json``
    """
    prefix = "did:web:"
    if not did.startswith(prefix):
        return None
    parts = did[len(prefix) :].split(":")
    domain = parts[0].replace("%3A", ":")
    if not domain:
        return None
    if len(parts) == 1:
        return f"https://{domain}/.well-known/did.json"
    return f"https://{domain}/" + "/".join(parts[1:]) + "/did.json"


def key_from_did_document(doc: Mapping[str, Any]) -> str | None:
    """The first Ed25519 ``publicKeyMultibase`` (``z…``) in a DID document's
    ``verificationMethod`` list, or None. This is the same multibase encoding a
    ``did:key`` uses, so it compares directly."""
    methods = doc.get("verificationMethod")
    if not isinstance(methods, list):
        return None
    for vm in methods:
        if isinstance(vm, dict):
            mb = vm.get("publicKeyMultibase")
            if isinstance(mb, str) and mb.startswith("z"):
                return mb
    return None


class DidWebResolver:
    """Resolve a canonical agent id's ``did:web`` to its key by fetching the
    document. ``transport`` is an injectable httpx transport for tests."""

    def __init__(
        self,
        *,
        did_for: DidFor = identity_did,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
    ) -> None:
        self.did_for = did_for
        self.timeout = timeout
        self._transport = transport
        self._label = label or "did:web"

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, DidView | None]:
        url = did_web_url(self.did_for(agent_id))
        if url is None:
            return "error", None
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
            doc = resp.json()
        except Exception:
            return "error", None
        if not isinstance(doc, dict):
            return "error", None
        key = key_from_did_document(doc)
        if key is None:
            return "error", None  # document present but no usable key is not a false key
        return "present", DidView(key=key)
