"""``python -m sm_divergence`` — one-shot divergence check for cron / CI.

    python -m sm_divergence check \
        --registry https://registry-a.example \
        --registry https://registry-b.example \
        --watch agent-1 --watch agent-2

Exit code is 0 when the registries agree, 2 when any divergence is found (so a
cron or CI step fails loudly), and 1 on a usage error.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence

from sm_resolver import Finding, Resolver

from .detector import check_once
from .discovery import DEFAULT_PATH, NandaIndexV2Resolver, RecordAdapter, RecordView, default_adapter

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_DIVERGENCE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sm_divergence", description="Catch a cheating registry by corroboration.")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="Compare registries for a set of ids.")
    check.add_argument(
        "--registry",
        action="append",
        default=[],
        metavar="URL",
        help="NEST-style by-id registry base URL (repeatable).",
    )
    check.add_argument(
        "--nanda-index",
        action="append",
        default=[],
        metavar="URL",
        help="NANDA Index v2 base URL — two-hop resolve (repeatable). Watch ids are used as locators.",
    )
    check.add_argument("--watch", action="append", default=[], metavar="ID", help="Agent id to compare (repeatable).")
    check.add_argument(
        "--path", default=DEFAULT_PATH, help=f"By-id path template for --registry (default: {DEFAULT_PATH})."
    )
    check.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout seconds (default: 10).")
    check.add_argument(
        "--attestation",
        action="store_true",
        help="Also compare verified DIDs from signed records (needs the 'attestation' extra).",
    )
    check.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    return parser


def _format_text(findings: list[Finding]) -> str:
    if not findings:
        return "OK — registries agree on all watched ids."
    lines = [f"DIVERGENCE — {len(findings)} finding(s):"]
    for f in findings:
        lines.append(f"  [{f.kind}] {f.agent_id}: {json.dumps(f.detail, sort_keys=True)}")
    return "\n".join(lines)


async def _run_check(args: argparse.Namespace) -> int:
    watch = [w for w in args.watch if w]
    http_registries = [r for r in args.registry if r]
    index_urls = [u for u in args.nanda_index if u]
    if len(http_registries) + len(index_urls) < 2:
        print("error: need at least two registries (--registry / --nanda-index) to corroborate", file=sys.stderr)
        return EXIT_USAGE
    if not watch:
        print("error: need at least one --watch id", file=sys.stderr)
        return EXIT_USAGE

    adapter: RecordAdapter = default_adapter
    if args.attestation:
        from .discovery import signed_record_adapter

        adapter = signed_record_adapter()

    registries: list[str | Resolver[RecordView]] = list(http_registries)
    registries += [NandaIndexV2Resolver(u, adapter=adapter, timeout=args.timeout) for u in index_urls]

    findings = await check_once(registries, watch, adapter=adapter, path=args.path, timeout=args.timeout)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], sort_keys=True, indent=2))
    else:
        print(_format_text(findings))
    return EXIT_DIVERGENCE if findings else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "check":
        return asyncio.run(_run_check(args))
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
