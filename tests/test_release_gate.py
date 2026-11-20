"""The release gate: refuse to publish a wheel whose kernel floor is not on PyPI.

The gate runs in the release workflow, where a wrong answer either ships a wheel
nobody can install or blocks a release that is safe. Both directions are pinned
here, for both ways development may resolve the kernel.
"""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_kernel_published.py"

GIT_SOURCE = """
[tool.uv.sources]
sm-resolver = { git = "https://example.invalid/sm-resolver", rev = "0000000" }
"""
PATH_SOURCE = """
[tool.uv.sources]
sm-resolver = { path = "../sm-resolver" }
"""


def run_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, deps: str, sources: str = "", on_pypi: tuple[str, ...] = ()
) -> int:
    spec = importlib.util.spec_from_file_location("check_kernel_published", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        f'[project]\nname = "x"\nversion = "1.0.0"\ndependencies = [{deps}]\n{sources}', encoding="utf-8"
    )
    monkeypatch.setattr(module, "PYPROJECT", pyproject)

    def fake_urlopen(url: str, timeout: float = 0) -> Any:
        assert url == "https://pypi.org/pypi/sm-resolver/json"
        return io.BytesIO(json.dumps({"releases": {v: [] for v in on_pypi}}).encode())

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    result: int = module.main()
    return result


@pytest.mark.parametrize("sources", ["", GIT_SOURCE])
def test_floor_on_pypi_is_safe_to_publish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sources: str) -> None:
    deps = '"httpx>=0.24", "sm-resolver>=0.7"'
    assert run_gate(tmp_path, monkeypatch, deps=deps, sources=sources, on_pypi=("0.6.0", "0.7.0")) == 0
    assert run_gate(tmp_path, monkeypatch, deps=deps, sources=sources, on_pypi=("0.7.1", "0.10.0")) == 0


@pytest.mark.parametrize("sources", ["", GIT_SOURCE])
def test_floor_ahead_of_pypi_refuses_to_publish(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, sources: str) -> None:
    deps = '"sm-resolver>=0.8"'
    assert run_gate(tmp_path, monkeypatch, deps=deps, sources=sources, on_pypi=("0.6.0", "0.7.0")) == 1
    assert run_gate(tmp_path, monkeypatch, deps=deps, sources=sources, on_pypi=()) == 1


def test_versions_compare_numerically_not_as_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_gate(tmp_path, monkeypatch, deps='"sm-resolver>=0.10"', on_pypi=("0.9.0",)) == 1
    assert run_gate(tmp_path, monkeypatch, deps='"sm-resolver>=0.9"', on_pypi=("0.10.0",)) == 0


def test_no_floor_is_a_configuration_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert run_gate(tmp_path, monkeypatch, deps='"httpx>=0.24"', on_pypi=("0.7.0",)) == 2
    assert run_gate(tmp_path, monkeypatch, deps='"sm-resolver==0.7.0"', on_pypi=("0.7.0",)) == 2


def test_an_override_that_is_not_a_git_source_is_a_configuration_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert run_gate(tmp_path, monkeypatch, deps='"sm-resolver>=0.7"', sources=PATH_SOURCE, on_pypi=("0.7.0",)) == 2


def test_the_gate_passes_on_this_checkout_as_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """The repository's own pyproject must be a shape the gate accepts.

    A gate that rejects the repository's own configuration blocks every release
    until someone notices; this fails in CI instead, on the change that causes it.
    """
    spec = importlib.util.spec_from_file_location("check_kernel_published", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def fake_urlopen(url: str, timeout: float = 0) -> Any:
        return io.BytesIO(json.dumps({"releases": {"99.0.0": []}}).encode())

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    assert module.main() == 0
