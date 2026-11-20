"""The stories: what Pim learns when it asks every place the booking agent is listed.

Each story builds a fresh world (world.py), changes what one source says, runs the sweep, and
checks the result. A sweep here is the library's own: one resolver per source, the kernel's
``Corroborator`` comparing their claims, and a signed Corroboration Record sealing the outcome.
Stories are plain coroutines so the tests run them in-process exactly as the site does.
"""

from __future__ import annotations

import copy
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from sm_resolver import Corroborator, SweepResult

from sm_divergence.discovery import RecordView
from sm_divergence.record import build_corroboration_record, verify_corroboration_record

from .world import AGENT_ID, CARD_URL, ELSEWHERE_URL, FQDN, World, expected_view

Emit = Callable[[str, str], None]
Result = SweepResult[RecordView]


@dataclass
class Ctx:
    run_id: str
    emit: Emit
    sweeper_key: bytes  # 32 raw Ed25519 bytes: the key this site signs records with
    checks: list[dict[str, Any]] = field(default_factory=list)
    records: list[dict[str, Any]] = field(default_factory=list)
    effects: dict[str, Any] = field(default_factory=dict)

    def log(self, actor: str, text: str) -> None:
        self.emit(actor, text)

    def check(self, name: str, ok: bool, detail: str | None = None) -> bool:
        self.checks.append({"name": name, "ok": bool(ok), **({"detail": detail} if detail else {})})
        self.emit("check", f"{'✓' if ok else '✗'} {name}" + (f" — {detail}" if detail and not ok else ""))
        return bool(ok)


def _where(claim: Any) -> str:
    return f"{claim.source} via {claim.vantage}" if claim.vantage else str(claim.source)


def _short(view: RecordView | None) -> str:
    """The claim as it is compared: the reduced view, not the source's own spelling."""
    if view is None:
        return "nothing to compare"
    reduced = view.comparable()
    digest = reduced.get("digest")
    return f"card at {reduced.get('endpoint')}, {f'{digest[:23]}…' if digest else 'no digest'}"


async def sweep(w: World, ctx: Ctx, label: str, *, log_keys: str | None, only: str | None = None) -> Result:
    """Ask every source, compare, sign. Says what each source claimed, in the order asked."""
    sources = [s for s in w.sources(log_keys=log_keys) if only is None or s.label == only]
    (result,) = await Corroborator(sources).check([FQDN])
    for claim in result.claims:
        if claim.status == "present":
            ctx.log("sm-divergence", f"{_where(claim)}: present — {_short(claim.view)}")
        elif claim.status == "absent":
            ctx.log("sm-divergence", f"{_where(claim)}: absent — it answered, and it does not list this agent")
        else:
            ctx.log(
                "sm-divergence",
                f"{_where(claim)}: no claim ({claim.outcome}) — kept for the record, left out of the comparison",
            )
    for finding in result.findings:
        ctx.log("sm-divergence", f"finding: {finding.kind} — {_finding_text(finding.kind, finding.detail)}")
    record = build_corroboration_record(result, sweeper_private_key=ctx.sweeper_key)
    ctx.records.append({"label": label, "record": record})
    ctx.log(
        "sm-divergence",
        f"verdict {result.verdict}; record {record['record_id'][:16]}… signed by {record['sweeper'][:20]}…",
    )
    return result


def _finding_text(kind: str, detail: Any) -> str:
    if not isinstance(detail, dict):
        return str(detail)
    if kind == "omission":
        return f"listed by {', '.join(detail['present_on'])}; missing from {', '.join(detail['missing_from'])}"
    if kind == "source_equivocation":
        return f"{detail['source']} gave different {detail['field']} values to {' and '.join(detail['values'])}"
    values = detail.get("values", {})
    groups: dict[str, list[str]] = {}
    for source, value in values.items():
        groups.setdefault(str(value), []).append(source)
    return "; ".join(f"{', '.join(sorted(who))} say {value}" for value, who in groups.items())


def _kinds(result: Result) -> set[str]:
    return {f.kind for f in result.findings}


def _claim(result: Result, source: str) -> Any:
    return next(c for c in result.claims if c.source == source)


def _present_views_match(result: Result) -> bool:
    want = expected_view().comparable()
    return all(c.view is not None and c.view.comparable() == want for c in result.claims if c.status == "present")


def _records_verify(ctx: Ctx) -> None:
    good = sum(1 for r in ctx.records if verify_corroboration_record(r["record"]))
    ctx.check(
        "every record's signature and content address verify", good == len(ctx.records), f"{good}/{len(ctx.records)}"
    )
    changed = copy.deepcopy(ctx.records[-1]["record"])
    changed["verdict"] = "AGREE" if changed["verdict"] != "AGREE" else "DIVERGENT"
    ctx.check("a record with its verdict changed no longer verifies", not verify_corroboration_record(changed))


def _ask(ctx: Ctx) -> None:
    ctx.log("John", "Pim, book the Lisbon trip with Travel26.")
    ctx.log(
        "Pim",
        "Before I send anything, I'm checking where Travel26's booking agent is listed: its zone (through two "
        "resolvers), a registry, a transparency log and Travel26's own catalog. They should all name the same agent card.",
    )


# --- the stories ----------------------------------------------------------------------------------


async def all_agree(w: World, ctx: Ctx) -> None:
    _ask(ctx)
    result = await sweep(w, ctx, "the sweep", log_keys=w.pinned_keys)
    ctx.check("verdict is AGREE", result.verdict == "AGREE", result.verdict)
    ctx.check(
        "five claims, all present: the zone twice, the registry, the log, the catalog",
        len(result.claims) == 5 and all(c.status == "present" for c in result.claims),
    )
    ctx.check(
        "three digest spellings (base64url, SHA256:hex, sha256:hex) reduce to one view", _present_views_match(result)
    )
    ctx.check("no findings", not result.findings)
    ctx.check(
        "the log's claim was read from its signed receipt and status token, not its unsigned badge",
        any(r.endswith("/receipt") for r in w.requests)
        and any(r.endswith("/status-token") for r in w.requests)
        and f"GET /log/v1/agents/{AGENT_ID}" not in w.requests,
    )
    _records_verify(ctx)
    ctx.log("Pim", "All five answers name the same card with the same digest. Booking.")


async def registry_points_elsewhere(w: World, ctx: Ctx) -> None:
    _ask(ctx)
    w.registry_points_elsewhere()
    alone = await sweep(w, ctx, "asking only the registry", log_keys=None, only="registry")
    ctx.check(
        "asked alone, the registry's answer looks fine: one claim, present",
        len(alone.claims) == 1 and alone.claims[0].status == "present",
    )
    ctx.check("one source is never AGREE: the verdict is INSUFFICIENT", alone.verdict == "INSUFFICIENT", alone.verdict)
    ctx.log("Pim", "One answer is nothing to compare. Asking the others.")
    result = await sweep(w, ctx, "asking every source", log_keys=w.pinned_keys)
    ctx.check("verdict is DIVERGENT", result.verdict == "DIVERGENT", result.verdict)
    ctx.check(
        "the finding is an endpoint disagreement, and nothing else", _kinds(result) == {"endpoint"}, str(_kinds(result))
    )
    values = result.findings[0].detail["values"] if result.findings else {}
    ctx.check(
        "it names the registry's card against the one the others give",
        values.get("registry") == ELSEWHERE_URL and values.get("zone") == CARD_URL,
    )
    _records_verify(ctx)
    ctx.log(
        "Pim",
        "Not booking. The registry names a different card from the zone, the log and the catalog. I can't tell "
        "from here which is right, only that they disagree, and I have a signed record saying so.",
    )


async def different_card(w: World, ctx: Ctx) -> None:
    _ask(ctx)
    w.catalog_lists_another_card()
    result = await sweep(w, ctx, "the sweep", log_keys=w.pinned_keys)
    ctx.check("verdict is DIVERGENT", result.verdict == "DIVERGENT", result.verdict)
    ctx.check("every source gives the same address", len({c.view.endpoint for c in result.claims if c.view}) == 1)
    ctx.check(
        "the finding is a digest disagreement, and nothing else", _kinds(result) == {"digest"}, str(_kinds(result))
    )
    ctx.check(
        "no document was fetched: the sources' stated digests are what is compared",
        not any("agent-card.json" in r for r in w.requests),
    )
    _records_verify(ctx)
    ctx.log(
        "Pim",
        "Same address everywhere, but the catalog expects a different document there than the others do. "
        "Either the card changed and someone hasn't caught up, or someone is describing a different card.",
    )


async def never_heard_of_it(w: World, ctx: Ctx) -> None:
    _ask(ctx)
    w.registry_forgets()
    result = await sweep(w, ctx, "the sweep", log_keys=w.pinned_keys)
    ctx.check(
        "the registry's claim is absent: it answered and does not list the agent",
        _claim(result, "registry").status == "absent",
    )
    ctx.check("verdict is DIVERGENT", result.verdict == "DIVERGENT", result.verdict)
    ctx.check(
        "the finding is an omission naming the registry",
        _kinds(result) == {"omission"} and result.findings[0].detail["missing_from"] == ["registry"],
        str(_kinds(result)),
    )
    _records_verify(ctx)
    ctx.log(
        "Pim",
        "Three places list this agent and one says it doesn't exist. Had I asked only that one, I'd have told "
        "you Travel26 has no booking agent.",
    )


async def split_view(w: World, ctx: Ctx) -> None:
    _ask(ctx)
    w.zone_answers_differently_from("resolver-b")
    result = await sweep(w, ctx, "the sweep", log_keys=w.pinned_keys)
    ctx.check("verdict is DIVERGENT", result.verdict == "DIVERGENT", result.verdict)
    ctx.check(
        "the finding is one source answering differently by vantage",
        _kinds(result) == {"source_equivocation"},
        str(_kinds(result)),
    )
    detail = result.findings[0].detail if result.findings else {}
    ctx.check(
        "it names the zone and both resolvers",
        detail.get("source") == "zone" and set(detail.get("values", {})) == {"resolver-a", "resolver-b"},
    )
    _records_verify(ctx)
    ctx.log(
        "Pim",
        "The same zone gave two answers depending on which resolver asked. Through one resolver alone I'd "
        "never have seen it.",
    )


async def source_down(w: World, ctx: Ctx) -> None:
    _ask(ctx)
    w.catalog_goes_down()
    result = await sweep(w, ctx, "the sweep", log_keys=w.pinned_keys)
    claim = _claim(result, "catalog")
    ctx.check(
        "the catalog's claim is an error with outcome unreachable",
        claim.status == "error" and claim.outcome == "unreachable",
        f"{claim.status}/{claim.outcome}",
    )
    ctx.check(
        "a source that is down is not reported as missing the agent: no omission finding",
        "omission" not in _kinds(result),
    )
    ctx.check("the four sources that answered agree: verdict AGREE", result.verdict == "AGREE", result.verdict)
    ctx.check(
        "the record still carries the failed claim",
        any(c["source"] == "catalog" and c["status"] == "error" for c in ctx.records[-1]["record"]["claims"]),
    )
    _records_verify(ctx)
    ctx.log(
        "Pim",
        "The catalog didn't answer. That isn't the catalog saying the agent is gone, so I don't treat it as "
        "that. The other four agree; the record shows the catalog was asked and failed.",
    )


async def revoked(w: World, ctx: Ctx) -> None:
    _ask(ctx)
    w.log_revokes()
    result = await sweep(w, ctx, "the sweep", log_keys=w.pinned_keys)
    claim = _claim(result, "log")
    ctx.check(
        "the log's status token verifies and says REVOKED: outcome revoked",
        claim.status == "error" and claim.outcome == "revoked",
        f"{claim.status}/{claim.outcome}",
    )
    ctx.check(
        "revoked is neither a card to compare nor a claim that the agent is absent",
        "omission" not in _kinds(result) and claim.view is None,
    )
    ctx.check(
        "the outcome is in the signed record, for a policy to act on",
        any(c["outcome"] == "revoked" for c in ctx.records[-1]["record"]["claims"]),
    )
    ctx.effects["policy"] = "stop on revoked"
    _records_verify(ctx)
    ctx.log(
        "Pim",
        "The zone, the registry and the catalog still agree on the card, so the sweep itself says AGREE. But the "
        "log says this registration was revoked, and your rule is to stop on that. Not booking.",
    )


async def forged_receipt(w: World, ctx: Ctx) -> None:
    _ask(ctx)
    w.zone_is_tampered()
    w.log_is_impersonated()
    ctx.log("Pim", "First, the way a client with no pinned key reads the log: as served.")
    served = await sweep(w, ctx, "log read as served", log_keys=None)
    ctx.check(
        "read as served, the impersonated log counts as a source backing the tampered zone",
        _claim(served, "log").status == "present" and _claim(served, "log").view.endpoint == ELSEWHERE_URL,
    )
    ctx.log("Pim", "Second: verify the receipt, with the key the log itself hands out.")
    fetched = await sweep(w, ctx, "log verified with the key it serves", log_keys=await w.fetch_log_keys())
    ctx.check(
        "verified against the key the responder serves, the forged receipt passes: self-consistent proves nothing",
        _claim(fetched, "log").status == "present" and _claim(fetched, "log").view.endpoint == ELSEWHERE_URL,
    )
    ctx.log("Pim", "Third: verify with the key John pinned when he first trusted this log.")
    pinned = await sweep(w, ctx, "log verified with the pinned key", log_keys=w.pinned_keys)
    claim = _claim(pinned, "log")
    ctx.check(
        "against the pinned key the receipt is refused: outcome unverifiable, no claim",
        claim.status == "error" and claim.outcome == "unverifiable",
        f"{claim.status}/{claim.outcome}",
    )
    values = pinned.findings[0].detail["values"] if pinned.findings else {}
    ctx.check(
        "the tampered zone now stands alone against the registry and the catalog",
        "log" not in values and values.get("zone") == ELSEWHERE_URL,
        str(sorted(values)),
    )
    ctx.check(
        "all three sweeps are DIVERGENT; what differs is who is counted on which side",
        {served.verdict, fetched.verdict, pinned.verdict} == {"DIVERGENT"},
    )
    _records_verify(ctx)
    ctx.log(
        "Pim",
        "Not booking. Two sources name a card elsewhere, but one of them is a log whose receipt doesn't verify "
        "against the key I already had. That leaves the zone on its own.",
    )


@dataclass(frozen=True)
class Story:
    name: str
    title: str
    text: str
    run: Callable[[World, Ctx], Awaitable[None]]


STORIES: dict[str, Story] = {
    s.name: s
    for s in [
        Story(
            "all-agree",
            "Everyone agrees",
            "Pim asks the zone through two resolvers, the registry, the log and the catalog. Five answers, three ways of "
            "writing a digest, one view. AGREE, and a signed record that the check ran.",
            all_agree,
        ),
        Story(
            "registry-points-elsewhere",
            "The registry points somewhere else",
            "Asked alone, the registry's answer looks fine. Asked alongside the others, it names a different agent card. "
            "DIVERGENT, with the finding naming who said what.",
            registry_points_elsewhere,
        ),
        Story(
            "different-card",
            "Same address, different card",
            "Every source gives the same address, but the catalog lists a different digest for the document there. "
            "Nothing is fetched: the sources' own statements disagree.",
            different_card,
        ),
        Story(
            "never-heard-of-it",
            "One source has never heard of it",
            "The registry answers 404, not registered, for an agent three other places list. That is an omission, and "
            "the record names the source.",
            never_heard_of_it,
        ),
        Story(
            "split-view",
            "The zone answers differently depending on who asks",
            "Through one resolver the zone names the usual card; through another, a different one. Same source, two "
            "vantages, two answers.",
            split_view,
        ),
        Story(
            "source-down",
            "A source is down",
            "The catalog returns 503. Down is not the same as absent: the sweep makes no claim for it, reports no "
            "omission, and the record shows it was asked.",
            source_down,
        ),
        Story(
            "revoked",
            "The registration was revoked",
            "The log's signed status token says REVOKED. That is neither a card to compare nor proof of absence; it is "
            "recorded as its own outcome for a policy to act on.",
            revoked,
        ),
        Story(
            "forged-receipt",
            "A forged receipt backs a tampered zone",
            "The zone is tampered with and someone impersonates the log to agree with it. Read as served, or verified "
            "with the key the impostor serves, the forgery counts. Against a pinned key it doesn't.",
            forged_receipt,
        ),
    ]
}


async def run_story(name: str, run_id: str, base: str, emit: Emit, sweeper_key: bytes) -> tuple[dict[str, Any], World]:
    """Run one story to completion. Returns the result and the world (kept so its sources can still be
    opened). Never raises for a story's own failure."""
    story = STORIES[name]
    ctx = Ctx(run_id, emit, sweeper_key)
    w = World(run_id, base, ctx.log)
    status, error = "passed", None
    try:
        await story.run(w, ctx)
        if not all(c["ok"] for c in ctx.checks):
            status = "failed"
    except Exception as e:  # a story crashing is a failed run, reported as such
        status, error = "error", f"{type(e).__name__}: {e}"
        ctx.emit("fault", error)
    result = {
        "status": status,
        "error": error,
        "checks": {"passed": sum(c["ok"] for c in ctx.checks), "total": len(ctx.checks), "items": ctx.checks},
        "records": ctx.records,
        "effects": ctx.effects,
        "sources": f"{w.base}/",
        "asked": list(w.requests),
    }
    return result, w
