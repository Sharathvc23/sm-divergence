"""Fetch one registry's claim about one id over HTTP, reduced to a RecordView.

The HTTP path and the record→RecordView mapping are both injectable, so this
works against any registry that answers a by-id query. The default targets the
common NEST-style ``GET /api/agents/{id}`` returning JSON with a top-level
``endpoint``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
from sm_resolver import Status

from .views import RecordView

# Maps a raw registry record (parsed JSON dict) to the discovery view.
RecordAdapter = Callable[[dict[str, Any]], RecordView]

DEFAULT_PATH = "/api/agents/{id}"


def default_adapter(record: dict[str, Any]) -> RecordView:
    """Read a top-level ``endpoint`` string; no DID (see
    ``sm_divergence.discovery.attestation`` for a signed-record adapter)."""
    ep = record.get("endpoint")
    return RecordView(endpoint=str(ep).rstrip("/") if isinstance(ep, str) and ep else None)


def looks_absent(doc: dict[str, Any]) -> bool:
    """A 200 body that actually means 'not found' — some registries soft-404
    with ``{"success": false, "error": "... not found"}`` instead of a 404.
    Shared by every HTTP resolver so soft-404 is classified consistently."""
    if doc.get("success") is False:
        return True
    return "not found" in str(doc.get("error") or "").lower()


async def fetch_view(
    client: httpx.AsyncClient,
    registry_url: str,
    agent_id: str,
    *,
    adapter: RecordAdapter = default_adapter,
    path: str = DEFAULT_PATH,
    timeout: float = 10.0,
) -> tuple[Status, RecordView | None]:
    """One registry's claim about one id (``present`` / ``absent`` / ``error``).
    Never raises."""
    url = registry_url.rstrip("/") + path.replace("{id}", agent_id)
    try:
        resp = await client.get(url, timeout=timeout)
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
        return "present", adapter(doc)
    except Exception:
        # A malformed record the adapter can't map is not a claim of absence.
        return "error", None
