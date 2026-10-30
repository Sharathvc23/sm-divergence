"""KnownSubjectResolver — the ``known-subject-resolution-02`` profile (POST
/resolve, one hop, terminal target), and every claim-state edge.

The shape under test is the registry-assisted resolution of a Known Subject
without a DNS Discovery Anchor. The resolver maps a Resolution Target Object
onto the discovery ``RecordView`` and its lease position onto the kernel's
``Binding``, so corroboration across such registries attributes lag as
``stale_binding`` and host-level substitution as ``digest``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sm_resolver import STALE_BINDING, Corroborator

from sm_divergence.discovery import DIGEST, ENDPOINT, KnownSubjectResolver, target_to_view
from sm_divergence.discovery.known_subject import OUTCOME_EXPIRED, OUTCOME_REVOKED

REG = "https://registry.example"
NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
LATER = (NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z")
EARLIER = (NOW - timedelta(hours=1)).isoformat().replace("+00:00", "Z")


def _target(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "subject": "orders@moon-bakery.example",
        "subjectType": "agent-name",
        "method": "artifact",
        "targetType": "application/a2a-agent-card+json",
        "targetUrl": "https://cards.agenthost.example/moon-bakery/orders.json",
        "targetDigest": "sha256:AAAA",
        "sequence": 8,
        "issuedAt": EARLIER,
        "expiresAt": LATER,
        "authority": {"type": "domain-control", "issuer": "https://registry.example"},
    }
    base.update(over)
    return base


def _response(targets: list[dict[str, Any]], *, registry_id: str = REG) -> dict[str, Any]:
    return {
        "registry": {"id": registry_id, "profile": "known-subject-resolution-02", "issuedAt": EARLIER},
        "subject": "orders@moon-bakery.example",
        "subjectType": "agent-name",
        "targets": targets,
    }


def _resolver(handler: Any, **kw: Any) -> KnownSubjectResolver:
    kw.setdefault("now", lambda: NOW)
    return KnownSubjectResolver(REG, transport=httpx.MockTransport(handler), **kw)


def _serve(resp: httpx.Response, *, capture: list[httpx.Request] | None = None) -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture.append(request)
        return resp

    return handler


# --- the request -------------------------------------------------------------


@pytest.mark.asyncio
async def test_request_is_post_resolve_with_identity_and_type() -> None:
    seen: list[httpx.Request] = []
    r = _resolver(_serve(httpx.Response(200, json=_response([_target()])), capture=seen))
    await r.resolve("orders@moon-bakery.example")
    (req,) = seen
    assert req.method == "POST"
    assert req.url.path == "/resolve"
    body = json.loads(req.content)
    assert body["identity"] == "orders@moon-bakery.example"
    assert body["identityType"] == "agent-name"
    assert body["acceptedMethods"] == ["artifact", "gateway"]
    assert 1 <= body["maxResults"] <= 100
    for forbidden in ("intent", "capabilityQuery", "nextRegistry"):
        assert forbidden not in body


@pytest.mark.asyncio
async def test_subject_for_maps_watch_id_to_identity_and_type() -> None:
    seen: list[httpx.Request] = []
    r = _resolver(
        _serve(httpx.Response(200, json=_response([_target()])), capture=seen),
        subject_for=lambda i: (f"{i}@example.net", "email"),
    )
    await r.resolve("alice")
    body = json.loads(seen[0].content)
    assert (body["identity"], body["identityType"]) == ("alice@example.net", "email")


# --- present ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_target_maps_to_view_with_digest_and_lease_position() -> None:
    status, view, outcome = await _resolver(
        _serve(httpx.Response(200, json=_response([_target()])))
    ).resolve_with_outcome("x")
    assert (status, outcome) == ("present", "present")
    assert view is not None
    assert view.endpoint == "https://cards.agenthost.example/moon-bakery/orders.json"
    assert view.digest == "sha256:AAAA"
    assert view.sequence == 8
    assert view.sequence_scope == "https://registry.example"
    assert view.authority_issuer == "https://registry.example"
    assert view.did is None
    binding = view.binding()
    assert binding is not None and (binding.sequence, binding.scope) == (8, "https://registry.example")


def test_comparable_carries_digest_but_never_issuer_or_sequence() -> None:
    view = target_to_view(_target())
    fields = view.comparable()
    assert set(fields) == {ENDPOINT, "did", DIGEST}
    assert "authority_issuer" not in fields and "sequence" not in fields


@pytest.mark.asyncio
async def test_first_non_fallback_target_is_selected() -> None:
    fallback = _target(targetUrl="https://fallback.example/card.json", fallback=True)
    primary = _target(targetUrl="https://primary.example/card.json")
    status, view = await _resolver(_serve(httpx.Response(200, json=_response([fallback, primary])))).resolve("x")
    assert status == "present" and view is not None
    assert view.endpoint == "https://primary.example/card.json"


@pytest.mark.asyncio
async def test_gateway_method_is_accepted_by_default() -> None:
    status, view = await _resolver(_serve(httpx.Response(200, json=_response([_target(method="gateway")])))).resolve(
        "x"
    )
    assert status == "present"


# --- absent ---------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_targets_is_absent() -> None:
    status, view, outcome = await _resolver(_serve(httpx.Response(200, json=_response([])))).resolve_with_outcome("x")
    assert (status, view, outcome) == ("absent", None, "absent")


@pytest.mark.asyncio
async def test_404_is_absent() -> None:
    status, view = await _resolver(_serve(httpx.Response(404))).resolve("x")
    assert (status, view) == ("absent", None)


# --- error, with the outcome that says why ----------------------------------------


@pytest.mark.asyncio
async def test_expired_binding_is_error_not_absent() -> None:
    status, view, outcome = await _resolver(
        _serve(httpx.Response(200, json=_response([_target(expiresAt=EARLIER)])))
    ).resolve_with_outcome("x")
    assert (status, view, outcome) == ("error", None, OUTCOME_EXPIRED)


@pytest.mark.asyncio
async def test_missing_expiry_is_unverifiable() -> None:
    t = _target()
    del t["expiresAt"]
    _, _, outcome = await _resolver(_serve(httpx.Response(200, json=_response([t])))).resolve_with_outcome("x")
    assert outcome == "unverifiable"


@pytest.mark.asyncio
async def test_revoked_target_is_error_revoked() -> None:
    _, _, outcome = await _resolver(
        _serve(httpx.Response(200, json=_response([_target(revoked=True)])))
    ).resolve_with_outcome("x")
    assert outcome == OUTCOME_REVOKED


@pytest.mark.asyncio
async def test_registry_as_target_is_refused() -> None:
    """A target MUST NOT be another generic Resolution Registry. A method this
    resolver did not accept is not followed."""
    _, _, outcome = await _resolver(
        _serve(httpx.Response(200, json=_response([_target(method="registry")])))
    ).resolve_with_outcome("x")
    assert outcome == "refused"


@pytest.mark.asyncio
async def test_provenance_from_another_registry_is_unverifiable() -> None:
    _, _, outcome = await _resolver(
        _serve(httpx.Response(200, json=_response([_target()], registry_id="https://other.example"))),
        expected_registry_id=REG,
    ).resolve_with_outcome("x")
    assert outcome == "unverifiable"


@pytest.mark.asyncio
async def test_matching_provenance_passes() -> None:
    status, _ = await _resolver(
        _serve(httpx.Response(200, json=_response([_target()]))), expected_registry_id=REG
    ).resolve("x")
    assert status == "present"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("code", "outcome"),
    [
        ("unverifiable", "unverifiable"),
        ("revoked", OUTCOME_REVOKED),
        ("stale", OUTCOME_EXPIRED),
        ("policy-rejected", "refused"),
        ("malformed-response", "unparseable"),
        ("something-new", "unverifiable"),
    ],
)
async def test_problem_details_code_maps_to_outcome(code: str, outcome: str) -> None:
    problem = {"type": f"https://registry.example/problems/{code}", "title": "t", "status": 422, "code": code}
    resp = httpx.Response(422, json=problem, headers={"content-type": "application/problem+json"})
    status, view, got = await _resolver(_serve(resp)).resolve_with_outcome("x")
    assert (status, view, got) == ("error", None, outcome)


@pytest.mark.asyncio
async def test_5xx_is_unreachable() -> None:
    _, _, outcome = await _resolver(_serve(httpx.Response(503))).resolve_with_outcome("x")
    assert outcome == "unreachable"


@pytest.mark.asyncio
async def test_timeout_is_timeout() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    _, _, outcome = await _resolver(handler).resolve_with_outcome("x")
    assert outcome == "timeout"


@pytest.mark.asyncio
async def test_unparseable_body_is_unparseable() -> None:
    _, _, outcome = await _resolver(_serve(httpx.Response(200, content=b"<html>"))).resolve_with_outcome("x")
    assert outcome == "unparseable"


@pytest.mark.asyncio
async def test_missing_sequence_is_unverifiable() -> None:
    t = _target()
    del t["sequence"]
    _, _, outcome = await _resolver(_serve(httpx.Response(200, json=_response([t])))).resolve_with_outcome("x")
    assert outcome == "unverifiable"


# --- corroboration across two resolution registries ----------------------------------


class _Fixed:
    def __init__(self, label: str, target: dict[str, Any]) -> None:
        self._label = label
        self._r = KnownSubjectResolver(
            f"https://{label}",
            transport=httpx.MockTransport(_serve(httpx.Response(200, json=_response([target])))),
            label=label,
            now=lambda: NOW,
        )

    @property
    def label(self) -> str:
        return self._label

    async def resolve_with_outcome(self, agent_id: str) -> Any:
        return await self._r.resolve_with_outcome(agent_id)

    async def resolve(self, agent_id: str) -> Any:
        return await self._r.resolve(agent_id)


@pytest.mark.asyncio
async def test_lagging_registry_is_stale_binding_not_endpoint_divergence() -> None:
    """Sequence 13 vs 14 under one issuer is propagation, not tampering."""
    current = _Fixed("a", _target(sequence=14, targetUrl="https://new.example/card.json", targetDigest="sha256:NEW"))
    behind = _Fixed("b", _target(sequence=13, targetUrl="https://old.example/card.json", targetDigest="sha256:OLD"))
    (res,) = await Corroborator([current, behind]).check(["x"])
    assert res.verdict == "DIVERGENT"
    assert [f.kind for f in res.findings] == [STALE_BINDING]
    assert res.findings[0].detail["source"] == "b"
    assert res.findings[0].detail["scope"] == "https://registry.example"


@pytest.mark.asyncio
async def test_same_endpoint_different_digest_is_digest_divergence() -> None:
    """Both registries are current and agree on the address; the documents
    behind it differ. That is host-level substitution, reported as ``digest``."""
    a = _Fixed("a", _target(targetDigest="sha256:AAAA"))
    b = _Fixed("b", _target(targetDigest="sha256:BBBB"))
    (res,) = await Corroborator([a, b]).check(["x"])
    assert sorted(f.kind for f in res.findings) == [DIGEST]


@pytest.mark.asyncio
async def test_different_issuers_are_not_a_divergence() -> None:
    """Two registries validating the same subject through different issuers is
    the ordinary multi-registry case. Their sequences live in different scopes
    and their issuers are provenance, not a compared field."""
    a = _Fixed("a", _target(sequence=2, authority={"type": "domain-control", "issuer": "https://a.example"}))
    b = _Fixed(
        "b", _target(sequence=900, authority={"type": "account-provider-assertion", "issuer": "https://b.example"})
    )
    (res,) = await Corroborator([a, b]).check(["x"])
    assert res.verdict == "AGREE"
