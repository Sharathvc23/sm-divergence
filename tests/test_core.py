"""The core kernel is layer-agnostic — it corroborates ANY view type, not just
the discovery ``RecordView``. This is the whole point of the core/discovery seam:
a future layer (identity, capability, evidence) supplies its own view + a thin
resolver and reuses the same diff/orchestration unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import pytest
from _sweep import kinds

from sm_divergence import Corroborator, Status, diff_views


# A stand-in for a future non-discovery view (e.g. an identity-layer key view).
@dataclass(frozen=True)
class KeyView:
    key: str | None = None

    def comparable(self) -> Mapping[str, str | None]:
        return {"key": self.key}


class FakeResolver:
    """A thin adapter over a canned {agent_id: (Status, KeyView|None)} table —
    exactly the shape a real per-format adapter reduces to."""

    def __init__(self, label: str, table: dict[str, tuple[Status, KeyView | None]]) -> None:
        self._label = label
        self._table = table

    @property
    def label(self) -> str:
        return self._label

    async def resolve(self, agent_id: str) -> tuple[Status, KeyView | None]:
        return self._table.get(agent_id, ("error", None))


def test_diff_is_generic_over_view_type() -> None:
    """The pure diff names findings after whatever field the view exposes — here
    ``key``, not ``endpoint``/``did`` — with no change to core code."""
    views: dict[str, dict[str, KeyView | None]] = {
        "src-a": {"x": KeyView(key="did:key:zAAA")},
        "src-b": {"x": KeyView(key="did:key:zBBB")},
    }
    findings = diff_views(views, ["x"])
    assert [f.kind for f in findings] == ["key"]
    assert findings[0].detail == {
        "field": "key",
        "values": {"src-a": "did:key:zAAA", "src-b": "did:key:zBBB"},
    }


@pytest.mark.asyncio
async def test_corroborator_drives_any_resolver_type() -> None:
    """A NANDA-style thin adapter needs only: a label, a resolve() returning a
    view, and the core Corroborator — no discovery internals."""
    a = FakeResolver("src-a", {"x": ("present", KeyView(key="did:key:zAAA"))})
    b = FakeResolver("src-b", {"x": ("present", KeyView(key="did:key:zBBB"))})
    emitted = []
    corr: Corroborator[KeyView] = Corroborator([a, b], on_finding=emitted.append)
    results = await corr.check(["x"])
    assert kinds(results) == ["key"]
    assert len(emitted) == 1
    assert corr.labels == ["src-a", "src-b"]


@pytest.mark.asyncio
async def test_corroborator_omission_and_no_claim() -> None:
    """Omission (present vs confirmed-absent) is universal; an ``error`` source
    makes no claim and is excluded — same rules as discovery, in the kernel."""
    present = FakeResolver("src-a", {"x": ("present", KeyView(key="k"))})
    absent = FakeResolver("src-b", {"x": ("absent", None)})
    unreachable = FakeResolver("src-c", {"x": ("error", None)})

    corr: Corroborator[KeyView] = Corroborator([present, absent, unreachable])
    results = await corr.check(["x"])
    found = [f for r in results for f in r.findings]
    assert [f.kind for f in found] == ["omission"]
    assert found[0].detail == {"present_on": ["src-a"], "missing_from": ["src-b"]}
