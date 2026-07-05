"""Pure-diff coverage — the heart of the detector, no I/O."""

from __future__ import annotations

from sm_divergence import RecordView, diff_views

A = "https://registry-a.example"
B = "https://registry-b.example"


def test_agreement_yields_nothing() -> None:
    views = {
        A: {"x": RecordView(endpoint="https://x.example")},
        B: {"x": RecordView(endpoint="https://x.example")},
    }
    assert diff_views(views, ["x"]) == []


def test_endpoint_divergence() -> None:
    views = {
        A: {"x": RecordView(endpoint="https://real.example")},
        B: {"x": RecordView(endpoint="https://attacker.example")},
    }
    findings = diff_views(views, ["x"])
    assert [f.kind for f in findings] == ["endpoint"]
    assert findings[0].detail["field"] == "endpoint"
    assert findings[0].detail["values"] == {A: "https://real.example", B: "https://attacker.example"}


def test_omission() -> None:
    views: dict[str, dict[str, RecordView | None]] = {
        A: {"x": RecordView(endpoint="https://x.example")},
        B: {"x": None},
    }
    findings = diff_views(views, ["x"])
    assert [f.kind for f in findings] == ["omission"]
    assert findings[0].detail == {"present_on": [A], "missing_from": [B]}


def test_did_divergence() -> None:
    views = {
        A: {"x": RecordView(endpoint="https://x.example", did="did:key:zAAA")},
        B: {"x": RecordView(endpoint="https://x.example", did="did:key:zBBB")},
    }
    assert [f.kind for f in diff_views(views, ["x"])] == ["did"]


def test_unreachable_is_not_omission() -> None:
    # 'x' simply not in B's mapping — B made no claim.
    views: dict[str, dict[str, RecordView | None]] = {
        A: {"x": RecordView(endpoint="https://x.example")},
        B: {},
    }
    assert diff_views(views, ["x"]) == []


def test_missing_endpoint_no_false_positive() -> None:
    views = {
        A: {"x": RecordView(endpoint="https://x.example")},
        B: {"x": RecordView(endpoint=None)},
    }
    assert diff_views(views, ["x"]) == []


def test_only_one_verified_did_is_not_divergence() -> None:
    views = {
        A: {"x": RecordView(endpoint="https://x.example", did="did:key:zAAA")},
        B: {"x": RecordView(endpoint="https://x.example", did=None)},
    }
    assert diff_views(views, ["x"]) == []


def test_ids_outside_watch_set_ignored() -> None:
    views: dict[str, dict[str, RecordView | None]] = {
        A: {"y": RecordView(endpoint="https://y.example")},
        B: {"y": None},
    }
    assert diff_views(views, ["x"]) == []


def test_multiple_findings_for_one_id() -> None:
    # both an omission (C absent) and an endpoint split (A vs B)
    views: dict[str, dict[str, RecordView | None]] = {
        A: {"x": RecordView(endpoint="https://a.example")},
        B: {"x": RecordView(endpoint="https://b.example")},
        "https://registry-c.example": {"x": None},
    }
    kinds = sorted(f.kind for f in diff_views(views, ["x"]))
    assert kinds == ["endpoint", "omission"]


def test_finding_fingerprint_is_stable_and_distinct() -> None:
    views = {
        A: {"x": RecordView(endpoint="https://a.example")},
        B: {"x": RecordView(endpoint="https://b.example")},
    }
    f1 = diff_views(views, ["x"])[0]
    f2 = diff_views(views, ["x"])[0]
    assert f1.fingerprint() == f2.fingerprint()
    other = diff_views({A: {"y": RecordView(endpoint="https://a.example")}, B: {"y": None}}, ["y"])[0]
    assert other.fingerprint() != f1.fingerprint()
