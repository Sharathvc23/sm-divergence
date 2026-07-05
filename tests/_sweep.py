"""Helpers for the check()-returns-SweepResult API (sm-resolver 0.2)."""

from __future__ import annotations

from collections.abc import Iterable

from sm_resolver import Finding, SweepResult, ViewT


def all_findings(results: Iterable[SweepResult[ViewT]]) -> list[Finding]:
    """Every finding across every subject in a sweep, in subject order."""
    out: list[Finding] = []
    for r in results:
        out.extend(r.findings)
    return out


def kinds(results: Iterable[SweepResult[ViewT]]) -> list[str]:
    return [f.kind for f in all_findings(results)]


def verdict_of(results: Iterable[SweepResult[ViewT]], agent_id: str) -> str:
    return next(r.verdict for r in results if r.agent_id == agent_id)
