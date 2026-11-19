"""CatalogResolver — a published AI Catalog document as a source.

A publisher may list the artifacts it offers — agent cards, server cards, nested
catalogs — in one JSON document, by convention at
``/.well-known/ai-catalog.json``:

    {"specVersion": "…", "entries": [
        {"identifier": "…", "type": "application/a2a-agent-card+json",
         "url": "https://…/agent-card.json", "digest": "sha256:…"}, …]}

That document is a claim about a known subject: the entry whose ``identifier``
names it says where the subject's descriptor is and, optionally, what it hashes
to. This adapter maps that claim onto the ``Resolver`` contract so a catalog
diffs against a registry, a zone or a log with no special-casing downstream.

**What an entry contributes.** ``url`` → ``endpoint`` (the descriptor: the same
thing a registry's terminal target and a zone's descriptor key name) and
``digest`` → ``digest``. An entry that carries its artifact inline (``data``)
has no address, so it contributes ``endpoint=None`` with its digest. A catalog
entry names no service endpoint and no key, so there is no ``did``.

**Selecting the entry.** ``identifier_for`` maps the canonical watch id to the
entry ``identifier`` (identity correspondence is the caller's; identifiers are
compared exactly). When the matched entry is itself an inline nested catalog —
one subject offered over several protocols — its children are the candidates.
``artifact_type`` keeps only candidates of one media type. Of several versions
of one identifier the latest is taken. Candidates that still reduce to different
views are ``error``: with several artifacts listed, ``artifact_type`` must be
set.

**Never a false ``absent``.** A catalog that was read in full and lists no such
identifier is a claim of absence. No catalog at any configured path is not — the
publisher said nothing — and neither is a catalog that delegates part of its
listing to another document this resolver was not told to read.

**No fan-out by default.** One instance reads one document. ``follow_nested``
lets it read nested catalogs referenced by ``url``, within ``max_depth`` and
``max_documents`` and never the same document twice. Artifacts are never
fetched, and a digest is never checked against content.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeGuard
from urllib.parse import urljoin

import httpx
from sm_resolver import (
    OUTCOME_REFUSED,
    OUTCOME_TIMEOUT,
    OUTCOME_UNPARSEABLE,
    OUTCOME_UNREACHABLE,
    Status,
)

from .views import RecordView, normalize_endpoint

IdentifierFn = Callable[[str], str]

WELL_KNOWN_CATALOG_PATH = "/.well-known/ai-catalog.json"
CATALOG_MEDIA_TYPE = "application/ai-catalog+json"

# No catalog document at any configured path: the publisher made no claim.
OUTCOME_NO_CATALOG = "ai.stellarminds.catalog.no-catalog"
# The subject was not found, but part of the listing lives in a nested catalog
# this resolver did not read, so absence cannot be claimed.
OUTCOME_NESTED_NOT_READ = "ai.stellarminds.catalog.nested-not-read"
# The catalog path answered with a redirect, and redirects were not being
# followed: the origin asked did not itself serve a catalog.
OUTCOME_REDIRECTED = "ai.stellarminds.catalog.redirected"
# Several candidate entries reduce to different views.
OUTCOME_AMBIGUOUS_ENTRY = "ai.stellarminds.catalog.ambiguous-entry"

_SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def identity_identifier(agent_id: str) -> str:
    """Default ``identifier_for``: the watch id already *is* the entry identifier."""
    return agent_id


def air_identifier(publisher: str, name: str, kind: str | None = None) -> str:
    """Build a ``urn:air:{publisher}:{name}[:{kind}]`` identifier."""
    parts = ["urn", "air", publisher, name] + ([kind] if kind else [])
    return ":".join(parts)


def entry_type(entry: dict[str, Any]) -> str | None:
    """The entry's artifact media type: ``type``, or the earlier ``mediaType`` name."""
    for member in ("type", "mediaType"):
        value = entry.get(member)
        if isinstance(value, str) and value:
            return value
    return None


def entry_to_view(entry: dict[str, Any]) -> RecordView:
    """Reduce one leaf CatalogEntry to the discovery view. Raises if malformed."""
    url, has_data = entry.get("url"), "data" in entry
    if (url is None) == (not has_data):
        raise ValueError("an entry carries exactly one of url and data")
    if url is not None and not (isinstance(url, str) and url):
        raise ValueError("url is not a non-empty string")
    digest = entry.get("digest")
    if digest is not None and not (isinstance(digest, str) and digest):
        raise ValueError("digest is not a non-empty string")
    return RecordView(endpoint=url, digest=digest)


def _is_catalog(doc: Any) -> TypeGuard[dict[str, Any]]:
    return isinstance(doc, dict) and isinstance(doc.get("specVersion"), str) and isinstance(doc.get("entries"), list)


def _version_key(entry: dict[str, Any]) -> tuple[int, int, int] | None:
    match = _SEMVER.match(str(entry.get("version", "")))
    return (int(match[1]), int(match[2]), int(match[3])) if match else None


def _updated_key(entry: dict[str, Any]) -> datetime | None:
    value = entry.get("updatedAt")
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00").replace("z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def latest_entries(entries: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Of several entries for one identifier, those of the latest version.

    Ordered by ``version`` when every entry carries a ``major.minor.patch`` one,
    else by ``updatedAt`` when every entry carries one. Entries that cannot be
    ordered are all returned, and the caller decides whether they agree.
    """
    if len(entries) < 2:
        return list(entries)
    for key in (_version_key, _updated_key):
        keys = [key(entry) for entry in entries]
        if all(k is not None for k in keys):
            best = max(k for k in keys if k is not None)
            return [entry for entry, k in zip(entries, keys, strict=True) if k == best]
    return list(entries)


@dataclass
class _Walk:
    matches: list[dict[str, Any]] = field(default_factory=list)
    unread: bool = False


class CatalogResolver:
    """Resolve a canonical id through one publisher's AI Catalog document.

    ``base_url`` is the publisher's origin, or the catalog document's own URL
    when ``catalog_paths`` is ``("",)``. ``catalog_paths`` are tried in order and
    the first that is served is the catalog (default: the well-known path).
    ``identifier_for`` maps the watch id to the entry identifier;
    ``artifact_type`` keeps candidates of one media type. ``follow_nested``
    reads nested catalogs referenced by ``url``. ``follow_redirects`` follows
    HTTP redirects (an apex that redirects to ``www``, say); off by default, so
    the claim is the asked origin's own, and a redirect is then ``error`` with
    outcome ``ai.stellarminds.catalog.redirected``. ``transport`` is an injectable
    httpx transport for tests. ``vantage`` is the observation context; run two
    instances with the same ``label`` and different vantages to detect a
    publisher that serves different catalogs by context.
    """

    def __init__(
        self,
        base_url: str,
        *,
        identifier_for: IdentifierFn = identity_identifier,
        artifact_type: str | None = None,
        catalog_paths: Sequence[str] = (WELL_KNOWN_CATALOG_PATH,),
        follow_nested: bool = False,
        follow_redirects: bool = False,
        max_depth: int = 4,
        max_documents: int = 16,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
        vantage: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.identifier_for = identifier_for
        self.artifact_type = artifact_type
        self.catalog_paths = tuple(catalog_paths) or (WELL_KNOWN_CATALOG_PATH,)
        self.follow_nested = follow_nested
        self.follow_redirects = follow_redirects
        self.max_depth = max(1, int(max_depth))
        self.max_documents = max(1, int(max_documents))
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.base_url
        self.vantage = vantage

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        status, view, _ = await self.resolve_with_outcome(agent_id)
        return status, view

    async def resolve_with_outcome(self, agent_id: str) -> tuple[Status, RecordView | None, str]:
        """Never raises. ``present``/``absent`` use their status as outcome."""
        try:
            identifier = self.identifier_for(agent_id)
        except Exception:
            return "error", None, OUTCOME_UNPARSEABLE
        if not isinstance(identifier, str) or not identifier:
            return "error", None, OUTCOME_UNPARSEABLE

        async with httpx.AsyncClient(transport=self._transport) as client:
            root_url = ""
            root: Any = None
            for path in self.catalog_paths:
                root_url = self.base_url + path
                doc, outcome = await self._fetch(client, root_url)
                if outcome == OUTCOME_NO_CATALOG:
                    continue
                if doc is None:
                    return "error", None, outcome
                root = doc
                break
            if root is None:
                return "error", None, OUTCOME_NO_CATALOG

            walk = _Walk()
            seen = {normalize_endpoint(root_url) or root_url}
            outcome = await self._walk(client, root, root_url, identifier, walk, seen, depth=1)
            if outcome:
                return "error", None, outcome

        if not walk.matches:
            if walk.unread:
                return "error", None, OUTCOME_NESTED_NOT_READ
            return "absent", None, "absent"
        return self._claim(walk.matches)

    async def _fetch(self, client: httpx.AsyncClient, url: str) -> tuple[Any, str]:
        """One catalog document, or ``(None, outcome)``."""
        try:
            resp = await client.get(
                url,
                headers={"Accept": f"{CATALOG_MEDIA_TYPE}, application/json"},
                timeout=self.timeout,
                follow_redirects=self.follow_redirects,
            )
        except httpx.TimeoutException:
            return None, OUTCOME_TIMEOUT
        except Exception:
            return None, OUTCOME_UNREACHABLE
        if resp.status_code == 404:
            return None, OUTCOME_NO_CATALOG
        if 300 <= resp.status_code < 400:
            return None, OUTCOME_REDIRECTED
        if resp.status_code in (401, 403):
            return None, OUTCOME_REFUSED
        if resp.status_code != 200:
            return None, OUTCOME_UNREACHABLE
        try:
            doc = resp.json()
        except Exception:
            return None, OUTCOME_UNPARSEABLE
        if not _is_catalog(doc):
            return None, OUTCOME_UNPARSEABLE
        return doc, ""

    async def _walk(
        self,
        client: httpx.AsyncClient,
        catalog: dict[str, Any],
        catalog_url: str,
        identifier: str,
        walk: _Walk,
        seen: set[str],
        *,
        depth: int,
    ) -> str:
        """Collect the entries that name ``identifier``. Returns an error outcome, or ``""``."""
        for entry in catalog["entries"]:
            if not isinstance(entry, dict):
                continue
            nested = entry_type(entry) == CATALOG_MEDIA_TYPE
            if entry.get("identifier") == identifier:
                walk.matches.append(await self._inlined(client, entry, catalog_url, seen, depth) if nested else entry)
                continue
            if not nested:
                continue
            # A nested catalog that is not itself the subject may still list it.
            inline = entry.get("data")
            if _is_catalog(inline):
                if depth < self.max_depth:
                    outcome = await self._walk(client, inline, catalog_url, identifier, walk, seen, depth=depth + 1)
                    if outcome:
                        return outcome
                else:
                    walk.unread = True
                continue
            url = entry.get("url")
            if not (isinstance(url, str) and url):
                continue
            target = urljoin(catalog_url, url)
            key = normalize_endpoint(target) or target
            if key in seen:
                continue
            if not self.follow_nested or depth >= self.max_depth or len(seen) >= self.max_documents:
                walk.unread = True
                continue
            seen.add(key)
            doc, outcome = await self._fetch(client, target)
            if doc is None:
                # A nested document that cannot be read leaves the listing incomplete.
                walk.unread = True
                continue
            outcome = await self._walk(client, doc, target, identifier, walk, seen, depth=depth + 1)
            if outcome:
                return outcome
        return ""

    async def _inlined(
        self, client: httpx.AsyncClient, entry: dict[str, Any], catalog_url: str, seen: set[str], depth: int
    ) -> dict[str, Any]:
        """A matched nested-catalog entry with its document inline, when it may be read."""
        url = entry.get("url")
        if _is_catalog(entry.get("data")) or not (isinstance(url, str) and url):
            return entry
        target = urljoin(catalog_url, url)
        key = normalize_endpoint(target) or target
        if not self.follow_nested or depth >= self.max_depth or len(seen) >= self.max_documents or key in seen:
            return entry
        seen.add(key)
        doc, _ = await self._fetch(client, target)
        if doc is None:
            return entry
        return {**{k: v for k, v in entry.items() if k != "url"}, "data": doc}

    def _claim(self, matches: list[dict[str, Any]]) -> tuple[Status, RecordView | None, str]:
        candidates: list[dict[str, Any]] = []
        for entry in latest_entries(matches):
            if entry_type(entry) == CATALOG_MEDIA_TYPE:
                inline = entry.get("data")
                if not _is_catalog(inline):
                    # The subject is a catalog this resolver holds no copy of.
                    return "error", None, OUTCOME_NESTED_NOT_READ
                children = [child for child in inline["entries"] if isinstance(child, dict)]
                if len(children) != len(inline["entries"]):
                    return "error", None, OUTCOME_UNPARSEABLE
                candidates.extend(children)
            else:
                candidates.append(entry)

        if any(entry_type(entry) is None for entry in candidates):
            return "error", None, OUTCOME_UNPARSEABLE
        if self.artifact_type is not None:
            candidates = [entry for entry in candidates if entry_type(entry) == self.artifact_type]
        candidates = [entry for entry in candidates if entry_type(entry) != CATALOG_MEDIA_TYPE]
        if not candidates:
            return "absent", None, "absent"

        views: dict[tuple[tuple[str, str | None], ...], RecordView] = {}
        for entry in candidates:
            try:
                view = entry_to_view(entry)
            except Exception:
                return "error", None, OUTCOME_UNPARSEABLE
            views[tuple(sorted(view.comparable().items()))] = view
        if len(views) > 1:
            return "error", None, OUTCOME_AMBIGUOUS_ENTRY
        return "present", next(iter(views.values())), "present"
