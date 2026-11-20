"""The live demo site.

A Starlette app: the landing page, a console where anyone runs a story live and watches the
parties' own log stream in, the latest result of each story, each run's four fictional sources
served under /runs/<id>/… (the same handlers the library asked), and a lookup that asks a real
domain's zone through the DNS-over-HTTPS resolvers this deployment is configured with.

A run's world lives in memory; the latest run of each story is also kept on disk so the pages have
something to show after a restart. Limits: three runs at a time, five per visitor every ten
minutes; an admin token lifts them.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sm_resolver import Corroborator
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from sm_divergence import __version__, _signing
from sm_divergence.discovery import DnsZoneResolver, DohQuery
from sm_divergence.discovery.dns_records import normalize_owner
from sm_divergence.record import CORROBORATION_VERSION, build_corroboration_record

from .stories import STORIES, run_story
from .world import World

HERE = Path(__file__).resolve().parent
PUBLIC = HERE / "public"
DATA = Path(os.environ.get("QUILT_DATA", HERE.parent / ".quilt-data"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
MAX_CONCURRENT, PER_IP, WINDOW, KEEP_RUNS = 3, 5, 600, 60


def _doh_resolvers() -> dict[str, str]:
    """LOOKUP_DOH="name=https://…/dns-query,name=https://…/dns-query": the resolvers the lookup asks."""
    out: dict[str, str] = {}
    for part in os.environ.get("LOOKUP_DOH", "").split(","):
        name, _, url = part.strip().partition("=")
        if name and url.startswith("https://"):
            out[name] = url
    return out


LOOKUP_DOH = _doh_resolvers()


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sweeper_key() -> bytes:
    """This site's Ed25519 key: 32 raw bytes, made once and kept on the data volume."""
    path = DATA / "sweeper.key"
    if not path.is_file():
        DATA.mkdir(parents=True, exist_ok=True)
        path.write_bytes(secrets.token_bytes(32))
        path.chmod(0o600)
    return path.read_bytes()


def sweeper_did() -> str:
    return _signing.did_key_from_pubkey(_signing.public_from_private(sweeper_key()))


@dataclass
class Run:
    id: str
    scenario: str
    started_at: str
    status: str = "running"
    finished_at: str | None = None
    timeline: list[dict[str, Any]] = field(default_factory=list)
    result: dict[str, Any] | None = None
    world: World | None = None
    listeners: list[asyncio.Queue[dict[str, Any]]] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        checks = self.result["checks"] if self.result else None
        return {
            "id": self.id,
            "scenario": self.scenario,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "checks": {"passed": checks["passed"], "total": checks["total"]} if checks else None,
        }

    def full(self) -> dict[str, Any]:
        return {**self.summary(), "timeline": self.timeline, "result": self.result}


class Site:
    def __init__(self) -> None:
        self.runs: dict[str, Run] = {}
        self.order: deque[str] = deque()
        self.latest: dict[str, dict[str, Any]] = {}
        self.running = 0
        self.by_ip: dict[str, deque[float]] = {}
        self.tasks: set[asyncio.Task[None]] = set()
        try:
            self.latest = json.loads((DATA / "latest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.latest = {}

    def admin(self, request: Request) -> bool:
        sent = request.headers.get("authorization", "")
        return bool(ADMIN_TOKEN) and secrets.compare_digest(sent, f"Bearer {ADMIN_TOKEN}")

    def allowed(self, request: Request) -> str | None:
        if self.admin(request):
            return None
        if self.running >= MAX_CONCURRENT:
            return "three runs are already in progress; try again in a moment"
        ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or (
            request.client.host if request.client else "unknown"
        )
        q = self.by_ip.setdefault(ip, deque())
        while q and q[0] < time.time() - WINDOW:
            q.popleft()
        if len(q) >= PER_IP:
            return "five runs every ten minutes per visitor; try again later"
        q.append(time.time())
        return None

    def _save_latest(self) -> None:
        try:
            DATA.mkdir(parents=True, exist_ok=True)
            tmp = DATA / "latest.json.tmp"
            tmp.write_text(json.dumps(self.latest), encoding="utf-8")
            tmp.replace(DATA / "latest.json")
        except OSError:
            pass  # the pages still have this process's runs

    def start(self, scenario: str, origin: str) -> Run:
        run = Run(id=uuid.uuid4().hex[:12], scenario=scenario, started_at=now())
        self.runs[run.id] = run
        self.order.append(run.id)
        while len(self.order) > KEEP_RUNS:
            self.runs.pop(self.order.popleft(), None)
        self.running += 1

        def emit(actor: str, text: str) -> None:
            self._push(run, {"actor": actor, "text": text, "at": now()})

        async def go() -> None:
            try:
                result, run.world = await run_story(scenario, run.id, f"{origin}/runs/{run.id}", emit, sweeper_key())
            except Exception as e:  # run_story catches story errors; this is the harness itself
                result = {
                    "status": "error",
                    "error": f"{type(e).__name__}: {e}",
                    "records": [],
                    "effects": {},
                    "checks": {"passed": 0, "total": 0, "items": []},
                    "sources": None,
                    "asked": [],
                }
            run.result = result
            run.status = result["status"]
            run.finished_at = now()
            self.running -= 1
            self.latest[scenario] = run.full()
            self._save_latest()
            done = f"run {run.status}: {result['checks']['passed']}/{result['checks']['total']} checks"
            self._push(run, {"actor": "site", "text": done, "at": now(), "done": True})

        task = asyncio.create_task(go())
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return run

    def _push(self, run: Run, entry: dict[str, Any]) -> None:
        if not entry.get("done"):
            run.timeline.append(entry)
        for q in list(run.listeners):
            q.put_nowait(entry)


site = Site()


def origin_of(request: Request) -> str:
    """The address visitors reach this site at: PUBLIC_URL, else what the proxy says, else the request."""
    if PUBLIC_URL:
        return PUBLIC_URL
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
    host = (
        request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc)).split(",")[0].strip()
    )
    return f"{scheme}://{host}"


def problem(code: str, text: str, status: int) -> JSONResponse:
    return JSONResponse({"error": code, "error_description": text}, status_code=status)


# --- routes --------------------------------------------------------------------------------------


async def index(request: Request) -> Response:
    return FileResponse(PUBLIC / "index.html")


async def console(request: Request) -> Response:
    return FileResponse(PUBLIC / "console.html")


async def health(request: Request) -> Response:
    return JSONResponse({"ok": True, "service": "sm-divergence-site", "version": __version__})


async def config(request: Request) -> Response:
    return JSONResponse(
        {
            "stories": [{"name": s.name, "title": s.title, "text": s.text} for s in STORIES.values()],
            "sweeper": sweeper_did(),
            "record_version": CORROBORATION_VERSION,
            "lookup": {"enabled": len(LOOKUP_DOH) >= 1, "vantages": sorted(LOOKUP_DOH)},
            "limits": {"concurrent": MAX_CONCURRENT, "per_ip": PER_IP, "window_seconds": WINDOW},
            "version": __version__,
        }
    )


async def key(request: Request) -> Response:
    return JSONResponse(
        {
            "sweeper": sweeper_did(),
            "alg": "EdDSA",
            "record_version": CORROBORATION_VERSION,
            "statement": "Every Corroboration Record this site issues is signed with the key this did:key encodes.",
        }
    )


async def admin_check(request: Request) -> Response:
    return JSONResponse({"ok": site.admin(request)})


async def start_run(request: Request) -> Response:
    try:
        body = await request.json()
    except ValueError:
        return problem("bad_request", "the body isn't JSON", 400)
    scenario = str(body.get("scenario", "")) if isinstance(body, dict) else ""
    if scenario not in STORIES:
        return problem("unknown_story", f"no story named {scenario!r}", 400)
    why = site.allowed(request)
    if why:
        return problem("rate_limited", why, 429)
    run = site.start(scenario, origin_of(request))
    return JSONResponse({"id": run.id, "scenario": scenario}, status_code=202)


async def list_runs(request: Request) -> Response:
    return JSONResponse([site.runs[i].summary() for i in reversed(site.order) if i in site.runs][:30])


async def get_run(request: Request) -> Response:
    run = site.runs.get(request.path_params["id"])
    if not run:
        return problem("not_found", "no run with that id", 404)
    return JSONResponse(run.full())


async def latest(request: Request) -> Response:
    return JSONResponse(site.latest)


async def events(request: Request) -> Response:
    run = site.runs.get(request.path_params["id"])
    if not run:
        return problem("not_found", "no run with that id", 404)
    q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    run.listeners.append(q)

    async def stream() -> Any:
        try:
            for entry in list(run.timeline):
                yield f"event: entry\ndata: {json.dumps(entry)}\n\n"
            if run.status != "running":
                yield f"event: done\ndata: {json.dumps(run.summary())}\n\n"
                return
            while True:
                try:
                    entry = await asyncio.wait_for(q.get(), timeout=15)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if entry.get("done"):
                    yield f"event: done\ndata: {json.dumps(run.summary())}\n\n"
                    return
                yield f"event: entry\ndata: {json.dumps(entry)}\n\n"
        finally:
            if q in run.listeners:
                run.listeners.remove(q)

    return StreamingResponse(
        stream(), media_type="text/event-stream", headers={"cache-control": "no-store", "x-accel-buffering": "no"}
    )


async def sources(request: Request) -> Response:
    """A run's fictional sources: the handlers the library asked, open to the visitor's browser."""
    run = site.runs.get(request.path_params["id"])
    if not run or run.world is None:
        return problem("not_found", "that run's sources are no longer kept; run the story again", 404)
    chunks: list[bytes] = []
    start: dict[str, Any] = {"status": 500, "headers": []}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            start.update(status=message["status"], headers=message.get("headers", []))
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    scope = {**request.scope, "root_path": ""}
    await run.world.app(scope, request.receive, send)
    headers = {k.decode(): v.decode() for k, v in start["headers"] if k.lower() != b"content-length"}
    return Response(b"".join(chunks), status_code=start["status"], headers=headers)


async def lookup(request: Request) -> Response:
    """Ask a real name's zone, through each configured resolver, whether it publishes an agent record.

    The name is only ever placed in a DNS question sent to this deployment's own resolvers: the
    site fetches nothing from an address a visitor supplies."""
    if not LOOKUP_DOH:
        return problem("lookup_disabled", "this deployment has no DNS-over-HTTPS resolver configured (LOOKUP_DOH)", 503)
    try:
        body = await request.json()
    except ValueError:
        return problem("bad_request", "the body isn't JSON", 400)
    name = normalize_owner(str(body.get("domain", "")).strip()) if isinstance(body, dict) else None
    if name is None or "." not in name:
        return problem("bad_request", "that isn't a domain name", 400)
    why = site.allowed(request)
    if why:
        return problem("rate_limited", why, 429)
    resolvers = [
        DnsZoneResolver(query=DohQuery(url, timeout=4.0), label="zone", vantage=vantage, timeout=4.0)
        for vantage, url in sorted(LOOKUP_DOH.items())
    ]
    try:
        (result,) = await asyncio.wait_for(Corroborator(resolvers).check([name]), timeout=12)
    except TimeoutError:
        return problem("timeout", "the resolvers took too long", 504)
    record = build_corroboration_record(result, sweeper_private_key=sweeper_key())
    return JSONResponse({"domain": name, "verdict": result.verdict, "record": record})


async def brand(request: Request) -> Response:
    name = request.path_params["file"]
    path = PUBLIC / "brand" / name
    if name not in ("stellarminds-mark.png", "favicon-32.png") or not path.is_file():
        return PlainTextResponse("not found", status_code=404)
    return FileResponse(path, headers={"cache-control": "public, max-age=86400"})


class SecurityHeaders:
    """A few response headers on everything, as pure ASGI."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = dict(message.get("headers", []))
                for k, v in (
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                ):
                    headers.setdefault(k, v)
                message = {**message, "headers": list(headers.items())}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def create_app() -> Starlette:
    routes = [
        Route("/", index),
        Route("/console", console),
        Route("/health", health),
        Route("/config", config),
        Route("/key", key),
        Route("/admin/check", admin_check),
        Route("/api/runs", start_run, methods=["POST"]),
        Route("/api/runs", list_runs),
        Route("/api/latest", latest),
        Route("/api/lookup", lookup, methods=["POST"]),
        Route("/api/runs/{id}", get_run),
        Route("/api/runs/{id}/events", events),
        Route("/runs/{id}", sources),
        Route("/runs/{id}/{path:path}", sources, methods=["GET", "POST"]),
        Route("/brand/{file}", brand),
        Mount("/static", app=StaticFiles(directory=str(HERE / "static")), name="static"),
    ]
    return Starlette(routes=routes, middleware=[Middleware(SecurityHeaders)])


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), proxy_headers=True, forwarded_allow_ips="*"
    )
