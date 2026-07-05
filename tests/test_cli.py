"""CLI — argument handling and exit codes (0 agree, 2 diverge, 1 usage)."""

from __future__ import annotations

import httpx
import pytest

from sm_divergence import cli

A = "https://registry-a.example"
B = "https://registry-b.example"


@pytest.fixture
def _route(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    routes: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        entry = routes.get(request.url.host)
        if isinstance(entry, int):
            return httpx.Response(entry, json={"detail": "not found"})
        return httpx.Response(200, json={"endpoint": entry})

    import sm_divergence.discovery.http_by_id as http_by_id
    import sm_divergence.discovery.index_v2 as idx

    orig = httpx.AsyncClient
    factory = lambda *a, **k: orig(transport=httpx.MockTransport(handler))  # noqa: E731
    monkeypatch.setattr(http_by_id.httpx, "AsyncClient", factory)
    monkeypatch.setattr(idx.httpx, "AsyncClient", factory)
    return routes


def test_agreement_exits_zero(_route: dict[str, object]) -> None:
    _route["registry-a.example"] = "https://x.example"
    _route["registry-b.example"] = "https://x.example"
    assert cli.main(["check", "--registry", A, "--registry", B, "--watch", "x"]) == cli.EXIT_OK


def test_divergence_exits_two(_route: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    _route["registry-a.example"] = "https://real.example"
    _route["registry-b.example"] = "https://attacker.example"
    code = cli.main(["check", "--registry", A, "--registry", B, "--watch", "x"])
    assert code == cli.EXIT_DIVERGENCE
    assert "DIVERGENCE" in capsys.readouterr().out


def test_json_output(_route: dict[str, object], capsys: pytest.CaptureFixture[str]) -> None:
    _route["registry-a.example"] = "https://real.example"
    _route["registry-b.example"] = "https://attacker.example"
    cli.main(["check", "--registry", A, "--registry", B, "--watch", "x", "--json"])
    out = capsys.readouterr().out
    assert '"kind": "endpoint"' in out


def test_one_registry_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check", "--registry", A, "--watch", "x"]) == cli.EXIT_USAGE
    assert "at least two" in capsys.readouterr().err


def test_no_watch_is_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["check", "--registry", A, "--registry", B]) == cli.EXIT_USAGE
    assert "at least one --watch" in capsys.readouterr().err


IDX = "https://index.example"


def test_mixed_registry_and_nanda_index_diverge(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A NEST-style --registry and a NANDA --nanda-index disagree on the endpoint."""

    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p == "/api/v1/resolve":
            return httpx.Response(200, json={"registry_url": "https://reg.example", "identifier": "x"})
        if p.startswith("/agents/"):  # NANDA hop 2
            return httpx.Response(200, json={"endpoint": "https://attacker.example"})
        return httpx.Response(200, json={"endpoint": "https://real.example"})  # NEST by-id

    import sm_divergence.discovery.http_by_id as http_by_id
    import sm_divergence.discovery.index_v2 as idx

    orig = httpx.AsyncClient
    factory = lambda *a, **k: orig(transport=httpx.MockTransport(handler))  # noqa: E731
    monkeypatch.setattr(http_by_id.httpx, "AsyncClient", factory)
    monkeypatch.setattr(idx.httpx, "AsyncClient", factory)

    code = cli.main(["check", "--registry", A, "--nanda-index", IDX, "--watch", "x"])
    assert code == cli.EXIT_DIVERGENCE
    assert "DIVERGENCE" in capsys.readouterr().out


def test_two_nanda_indexes_satisfy_minimum(monkeypatch: pytest.MonkeyPatch) -> None:
    """Two --nanda-index registries (no --registry) still corroborate."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/resolve":
            return httpx.Response(200, json={"registry_url": "https://reg.example", "identifier": "x"})
        return httpx.Response(200, json={"endpoint": "https://x.example"})

    import sm_divergence.discovery.index_v2 as idx

    orig = httpx.AsyncClient
    monkeypatch.setattr(idx.httpx, "AsyncClient", lambda *a, **k: orig(transport=httpx.MockTransport(handler)))

    code = cli.main(["check", "--nanda-index", IDX, "--nanda-index", "https://index-b.example", "--watch", "x"])
    assert code == cli.EXIT_OK
