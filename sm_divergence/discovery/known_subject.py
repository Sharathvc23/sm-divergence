"""KnownSubjectResolver — a THIN adapter for registry-assisted resolution of a
Known Subject (the ``known-subject-resolution-02`` profile).

The profile is the DAWN-aligned shape a Resolution Registry exposes when a
discovering entity already knows the Subject Identity and has no usable DNS
Discovery Anchor for it:

    POST {base}/resolve
    {"identity": "...", "identityType": "...", "maxResults": n,
     "acceptedMethods": ["artifact", "gateway"]}

    200 → {"registry": {...provenance...}, "subject": "...", "subjectType": "...",
           "targets": [ Resolution Target Object, ... ]}

One hop. The registry returns a *terminal* target — an artifact (an Agent Card,
an MCP descriptor) or a subject-authorized gateway — never another registry. That
is the boundary this profile draws, and it is the opposite of the two-hop
"index points, registry proves" shape ``NandaIndexV2Resolver`` adapts; under
this profile an index is one registry among several, and the sweep compares
registries directly.

What this resolver does with a target:

- ``targetUrl`` → ``endpoint``; ``targetDigest`` → ``digest``. Two registries
  agreeing on the address but not the digest have resolved to one host serving
  two documents, which the diff reports as ``digest``, a kind the endpoint
  comparison cannot express.
- ``sequence`` and ``authority.issuer`` → the view's lease position. The kernel
  reads it (``RecordView.binding()``) so a registry serving a superseded binding
  is attributed as ``stale_binding`` rather than compared against the current
  one. Sequences count within one authority scope, so the issuer is the scope.
- ``expiresAt`` in the past, or a target the registry itself marks revoked, is
  an ``error`` claim — a binding the profile says MUST be treated as stale is not
  a claim of absence — with outcome ``expired`` / ``revoked`` so the pattern is
  visible per source.
- An empty ``targets`` array is ``absent``: the registry answered and holds no
  public binding. A 404 is ``absent`` too. Any other failure is ``error``.
- Problem Details (RFC 9457) on 4xx carry a ``code``; it is mapped onto the
  outcome vocabulary rather than invented: ``unverifiable``, ``revoked``,
  ``stale`` → ``unverifiable``; ``policy-rejected`` → ``refused``;
  ``malformed-response`` → ``unparseable``.

What it does NOT do, by design:

- It does not evaluate Authority Evidence. The profile separates registry
  provenance from subject authority; whether a target's authority is acceptable
  is local policy, and a corroborator that let it change the verdict would be
  doing trust evaluation. The issuer is carried for the record as provenance.
- It does not fan out. One configured registry per instance; the sweep's source
  set is the bounded, explicitly configured set the profile requires of any
  resolver, and the sweep is an exact lookup, never an enumeration.
- It does not select the "best" of several targets. ``select`` picks one target
  for the view (default: the first non-fallback target whose method was
  accepted); a layer that wants every target as its own claim runs one instance
  per method. Multi-target comparison inside one response is a different
  question from corroboration across registries, and is not this resolver's.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

import httpx
from sm_resolver import (
    OUTCOME_REFUSED,
    OUTCOME_TIMEOUT,
    OUTCOME_UNPARSEABLE,
    OUTCOME_UNREACHABLE,
    OUTCOME_UNVERIFIABLE,
    Status,
)

from .views import RecordView

#: The profile identifier a conforming registry reports in its provenance.
RESOLUTION_PROFILE = "known-subject-resolution-02"

DEFAULT_RESOLVE_PATH = "/resolve"
DEFAULT_ACCEPTED_METHODS: tuple[str, ...] = ("artifact", "gateway")

# Outcomes this adapter adds to the seeded vocabulary (draft -02 seeds them;
# bare names are reserved for seeded values). They describe why a resolve
# ended as `error`; per SPEC.md §2a an outcome never affects which claims enter
# the diff.
OUTCOME_EXPIRED = "expired"
OUTCOME_REVOKED = "revoked"

# RFC 9457 `code` → outcome. Unknown codes fall back to `unverifiable`, the
# least specific honest reading of "the registry answered and the binding is
# not usable".
_PROBLEM_CODE_OUTCOME: dict[str, str] = {
    "unverifiable": OUTCOME_UNVERIFIABLE,
    "revoked": OUTCOME_REVOKED,
    "stale": OUTCOME_EXPIRED,
    "policy-rejected": OUTCOME_REFUSED,
    "malformed-response": OUTCOME_UNPARSEABLE,
    "unsupported-target": OUTCOME_REFUSED,
}

#: Maps a canonical watch id to the ``(identity, identityType)`` the registry
#: is asked for. Identity correspondence is the caller's to define, as for the
#: other resolvers: the same subject may be a bare id on one source and an
#: ``agent-name`` on another.
SubjectFn = Callable[[str], tuple[str, str]]

#: Chooses which target becomes the view. ``None`` means no usable target.
SelectFn = Callable[[Sequence[dict[str, Any]]], "dict[str, Any] | None"]


def agent_name_subject(agent_id: str) -> tuple[str, str]:
    """Default ``subject_for``: the watch id is an ``agent-name``."""
    return agent_id, "agent-name"


def _parse_rfc3339(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _sequence(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def target_to_view(target: dict[str, Any]) -> RecordView:
    """Reduce one Resolution Target Object to the discovery view.

    ``targetUrl`` is the endpoint; ``targetDigest`` the digest; ``sequence`` and
    ``authority.issuer`` the lease position. No ``did`` — this profile carries
    Authority Evidence, not an agent-signed record, and a DID enters the view
    only when verified (see ``attestation.signed_record_adapter``).
    """
    url = target.get("targetUrl")
    digest = target.get("targetDigest")
    authority = target.get("authority")
    issuer = authority.get("issuer") if isinstance(authority, dict) else None
    return RecordView(
        endpoint=url.rstrip("/") if isinstance(url, str) and url else None,
        digest=digest if isinstance(digest, str) and digest else None,
        sequence=_sequence(target.get("sequence")),
        sequence_scope=issuer if isinstance(issuer, str) and issuer else None,
        authority_issuer=issuer if isinstance(issuer, str) and issuer else None,
    )


def first_non_fallback(targets: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """Default ``select``: the first target not marked ``fallback``, else the
    first target. The profile orders nothing, so this is a stable rather than a
    meaningful choice; a deployment with a policy supplies its own."""
    for t in targets:
        if not t.get("fallback"):
            return t
    return targets[0] if targets else None


class KnownSubjectResolver:
    """Resolve a Known Subject through one Resolution Registry (one hop).

    ``registry_url`` is the registry's configured base URI. ``expected_registry_id``
    — if given, the response's ``registry.id`` must equal it, else the claim is
    ``error``/``unverifiable``: provenance from a registry other than the one
    configured is not a claim by the one configured. ``accepted_methods``
    constrains the target classes requested. ``transport`` is an injectable httpx
    transport for tests; ``None`` uses the real network. ``vantage`` is the
    observation context (SPEC.md §3a); run two instances with the same ``label``
    and different vantages to detect a registry that equivocates by context.
    ``now`` is injectable for expiry evaluation in tests.
    """

    def __init__(
        self,
        registry_url: str,
        *,
        subject_for: SubjectFn = agent_name_subject,
        accepted_methods: Sequence[str] = DEFAULT_ACCEPTED_METHODS,
        max_results: int = 3,
        select: SelectFn = first_non_fallback,
        expected_registry_id: str | None = None,
        resolve_path: str = DEFAULT_RESOLVE_PATH,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        label: str | None = None,
        vantage: str | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.registry_url = registry_url.rstrip("/")
        self.subject_for = subject_for
        self.accepted_methods = tuple(accepted_methods)
        self.max_results = max(1, min(100, int(max_results)))
        self.select = select
        self.expected_registry_id = expected_registry_id
        self.resolve_path = resolve_path
        self.timeout = timeout
        self._transport = transport
        self._label = label or self.registry_url
        self.vantage = vantage
        self._now = now or (lambda: datetime.now(UTC))

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, RecordView | None]:
        status, view, _ = await self.resolve_with_outcome(agent_id)
        return status, view

    async def resolve_with_outcome(self, agent_id: str) -> tuple[Status, RecordView | None, str]:
        """Never raises. ``present``/``absent`` use their status as outcome."""
        identity, identity_type = self.subject_for(agent_id)
        body = {
            "identity": identity,
            "identityType": identity_type,
            "maxResults": self.max_results,
            "acceptedMethods": list(self.accepted_methods),
        }
        try:
            async with httpx.AsyncClient(transport=self._transport) as client:
                resp = await client.post(
                    f"{self.registry_url}{self.resolve_path}",
                    json=body,
                    headers={"Accept": "application/json"},
                    timeout=self.timeout,
                )
        except httpx.TimeoutException:
            return "error", None, OUTCOME_TIMEOUT
        except Exception:
            return "error", None, OUTCOME_UNREACHABLE

        if resp.status_code == 404:
            return "absent", None, "absent"
        if 400 <= resp.status_code < 500:
            return "error", None, self._problem_outcome(resp)
        if resp.status_code != 200:
            return "error", None, OUTCOME_UNREACHABLE

        try:
            doc = resp.json()
        except Exception:
            return "error", None, OUTCOME_UNPARSEABLE
        if not isinstance(doc, dict):
            return "error", None, OUTCOME_UNPARSEABLE

        registry = doc.get("registry")
        if self.expected_registry_id is not None:
            rid = registry.get("id") if isinstance(registry, dict) else None
            if rid != self.expected_registry_id:
                return "error", None, OUTCOME_UNVERIFIABLE

        targets = doc.get("targets")
        if not isinstance(targets, list):
            return "error", None, OUTCOME_UNPARSEABLE
        if not targets:
            return "absent", None, "absent"
        usable = [t for t in targets if isinstance(t, dict)]
        if len(usable) != len(targets):
            return "error", None, OUTCOME_UNPARSEABLE

        # The profile forbids a registry as the terminal target. A target that
        # names one is a profile violation; the registry answered, but with
        # something this resolver may not follow.
        usable = [t for t in usable if t.get("method") in self.accepted_methods]
        if not usable:
            return "error", None, OUTCOME_REFUSED

        target = self.select(usable)
        if target is None:
            return "error", None, OUTCOME_REFUSED

        if target.get("revoked") is True:
            return "error", None, OUTCOME_REVOKED
        expires = _parse_rfc3339(target.get("expiresAt"))
        if expires is None:
            # expiresAt is REQUIRED on every target; a binding with no expiry
            # cannot be evaluated for freshness and is not a claim.
            return "error", None, OUTCOME_UNVERIFIABLE
        if expires <= self._now():
            return "error", None, OUTCOME_EXPIRED
        if _sequence(target.get("sequence")) is None:
            return "error", None, OUTCOME_UNVERIFIABLE

        try:
            view = target_to_view(target)
        except Exception:
            return "error", None, OUTCOME_UNPARSEABLE
        if view.endpoint is None:
            return "error", None, OUTCOME_UNPARSEABLE
        return "present", view, "present"

    @staticmethod
    def _problem_outcome(resp: httpx.Response) -> str:
        try:
            doc = resp.json()
        except Exception:
            return OUTCOME_UNVERIFIABLE
        code = doc.get("code") if isinstance(doc, dict) else None
        if not isinstance(code, str):
            return OUTCOME_UNVERIFIABLE
        return _PROBLEM_CODE_OUTCOME.get(code, OUTCOME_UNVERIFIABLE)
