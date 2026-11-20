"""The demo site: every story passes its own checks in-process, and the HTTP surface behaves."""

from __future__ import annotations

import asyncio
import copy
import importlib
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

pytest.importorskip("starlette")  # the site extra

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo import stories as stories_mod  # noqa: E402
from demo.world import AGENT_ID, FQDN  # noqa: E402
from sm_divergence.record import verify_corroboration_record  # noqa: E402

KEY = bytes(range(32))
BASE = "https://quilt.test/runs/test1234"


@pytest.mark.parametrize("name", list(stories_mod.STORIES))
async def test_story_passes_its_checks(name: str) -> None:
    log: list[tuple[str, str]] = []
    result, world = await stories_mod.run_story(
        name, "test1234", BASE, lambda actor, text: log.append((actor, text)), KEY
    )
    failed = [c for c in result["checks"]["items"] if not c["ok"]]
    assert result["status"] == "passed", (result["error"], failed, log[-5:])
    assert result["checks"]["total"] >= 5 and not failed
    assert result["records"], "every story ends with at least one signed record"
    for entry in result["records"]:
        record = entry["record"]
        assert verify_corroboration_record(record) and record["subject"]["agent_id"] == FQDN
        changed = copy.deepcopy(record)
        changed["claims"][0]["status"] = "absent" if changed["claims"][0]["status"] != "absent" else "present"
        assert not verify_corroboration_record(changed)
    assert result["asked"], "the library reached the sources over HTTP"
    assert world.base == BASE


async def test_a_storys_fault_is_in_a_source_not_in_the_library() -> None:
    result, world = await stories_mod.run_story("never-heard-of-it", "test1234", BASE, lambda *_: None, KEY)
    async with httpx.AsyncClient(transport=world.transport) as client:
        assert (await client.get(f"{BASE}/registry/ans/agents/{AGENT_ID}")).status_code == 404
        assert (await client.get(f"{BASE}/catalog/.well-known/ai-catalog.json")).status_code == 200
        assert FQDN in (await client.get(f"{BASE}/dns/resolver-a/zone")).text


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("QUILT_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("ADMIN_TOKEN", "secret-admin")
    monkeypatch.delenv("LOOKUP_DOH", raising=False)
    monkeypatch.delenv("PUBLIC_URL", raising=False)
    return importlib.reload(importlib.import_module("demo.server"))  # a fresh Site with this test's environment


async def test_site_http_surface(server: Any) -> None:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="https://quilt.test") as c:
        assert (await c.get("/health")).json()["ok"]
        cfg = (await c.get("/config")).json()
        assert {s["name"] for s in cfg["stories"]} == set(stories_mod.STORIES)
        assert cfg["sweeper"].startswith("did:key:z6Mk") and cfg["lookup"] == {"enabled": False, "vantages": []}
        assert (await c.get("/key")).json()["sweeper"] == cfg["sweeper"]
        page = await c.get("/")
        assert page.status_code == 200 and b"sm-divergence" in page.content
        assert page.headers["x-frame-options"] == "DENY"
        assert (await c.get("/console")).status_code == 200
        assert (await c.get("/static/verify.js")).status_code == 200
        assert (await c.get("/brand/stellarminds-mark.png")).status_code == 200
        assert (await c.get("/brand/other.png")).status_code == 404

        assert (await c.post("/api/runs", json={"scenario": "nope"})).status_code == 400
        assert (await c.post("/api/lookup", json={"domain": "agent.example.com"})).status_code == 503
        assert (await c.get("/api/runs/missing")).status_code == 404
        assert (await c.get("/runs/missing/")).status_code == 404

        started = await c.post("/api/runs", json={"scenario": "split-view"})
        assert started.status_code == 202
        run_id = started.json()["id"]
        for _ in range(100):
            run = (await c.get(f"/api/runs/{run_id}")).json()
            if run["status"] != "running":
                break
            await asyncio.sleep(0.05)
        assert run["status"] == "passed" and run["result"]["sources"] == f"https://quilt.test/runs/{run_id}/"
        record = run["result"]["records"][-1]["record"]
        assert record["sweeper"] == cfg["sweeper"] and record["verdict"] == "DIVERGENT"
        assert verify_corroboration_record(record, trusted_sweeper=cfg["sweeper"])

        # the run's sources stay open: the same handlers the library asked
        listing = (await c.get(f"/runs/{run_id}/")).json()
        assert listing["subject"] == FQDN
        zones = [(await c.get(url)).text for url in listing["sources"]["zone"].values()]
        assert zones[0] != zones[1], "the split view is in the zone itself"
        assert (await c.get(listing["sources"]["catalog"])).json()["entries"]
        assert (await c.get(listing["sources"]["log_keys"])).text.count("+") >= 2

        assert (await c.get("/api/latest")).json()["split-view"]["id"] == run_id
        assert [r["id"] for r in (await c.get("/api/runs")).json()] == [run_id]
        async with c.stream("GET", f"/api/runs/{run_id}/events") as events:
            text = "".join([chunk async for chunk in events.aiter_text()])
        assert "event: entry" in text and text.rstrip().splitlines()[-2] == "event: done"


async def test_limits_apply_without_the_admin_token(server: Any) -> None:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app), base_url="https://quilt.test") as c:
        codes = []
        for _ in range(server.PER_IP + 1):
            codes.append((await c.post("/api/runs", json={"scenario": "all-agree"})).status_code)
            await asyncio.sleep(0.2)
        assert codes[-1] == 429 and codes[0] == 202
        lifted = await c.post(
            "/api/runs", json={"scenario": "all-agree"}, headers={"authorization": "Bearer secret-admin"}
        )
        assert lifted.status_code == 202
        await asyncio.sleep(0.3)
