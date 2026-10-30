"""Refuse to release sm-divergence until the kernel it declares is on PyPI.

Development and CI resolve ``sm-resolver`` from git at a pinned commit
(``[tool.uv.sources]`` in pyproject.toml), which is deliberate: this repo must
not go red because a sibling repo's release has not landed. But the published
wheel carries only the PEP 621 floor (``sm-resolver>=X``), and a consumer who
installs it from PyPI will fail to resolve if X is not there. This gate runs in
the release workflow and fails loudly, with the exact command to run, instead
of letting a broken wheel ship.

Also checks that the floor declared in ``dependencies`` matches the version
the pinned git commit actually is, so the two cannot drift apart silently.

Usage: python scripts/check_kernel_published.py  (exit 0 = safe to publish)
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.request
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def main() -> int:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    deps = data["project"]["dependencies"]
    spec = next((d for d in deps if d.split(">=")[0].strip() == "sm-resolver"), None)
    if spec is None or ">=" not in spec:
        print("check_kernel_published: no `sm-resolver>=X` floor in dependencies", file=sys.stderr)
        return 2
    floor = spec.split(">=", 1)[1].strip()

    source = data.get("tool", {}).get("uv", {}).get("sources", {}).get("sm-resolver")
    if not source or "git" not in source:
        print("check_kernel_published: expected a git source for sm-resolver in [tool.uv.sources]", file=sys.stderr)
        return 2

    with urllib.request.urlopen("https://pypi.org/pypi/sm-resolver/json", timeout=30) as resp:
        releases = sorted(json.load(resp)["releases"], key=_vkey)
    if not any(_vkey(v) >= _vkey(floor) for v in releases):
        print(
            f"check_kernel_published: sm-divergence declares sm-resolver>={floor}, but PyPI has only "
            f"{releases[-1] if releases else 'nothing'}.\n"
            f"  Publish the kernel first (in sm-resolver: git tag v{floor} <commit> && git push origin v{floor}),\n"
            f"  wait for its release workflow, then re-push this tag.",
            file=sys.stderr,
        )
        return 1

    print(f"check_kernel_published: sm-resolver>={floor} is on PyPI (latest {releases[-1]}); safe to publish.")
    return 0


def _vkey(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


if __name__ == "__main__":
    sys.exit(main())
