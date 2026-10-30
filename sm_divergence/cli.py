"""``python -m sm_divergence`` — one-shot divergence check for cron / CI.

    python -m sm_divergence check \
        --resolution-registry https://registry-a.example \
        --resolution-registry https://registry-b.example \
        --watch orders@moon-bakery.example

(``--resolution-registry`` is a Resolution Registry implementing the
``known-subject-resolution-02`` profile; ``--registry`` is a NEST-style by-id
registry; ``--nanda-index`` the legacy two-hop Index. They mix freely.)

Exit code is 0 when every watched id agrees (or is INSUFFICIENT), 2 when any id
is DIVERGENT (so a cron or CI step fails loudly), and 1 on a usage error.

Pass ``--sweeper-key PATH`` (a file of 64 hex chars = 32 raw Ed25519 bytes) to
emit a signed Corroboration Record per subject instead of a findings summary —
the auditable, content-addressed attestation that the sweep ran (draft §9). This
needs the ``attestation`` extra.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Sequence

from sm_resolver import Resolver, SweepResult

from .detector import check_once
from .discovery import (
    DEFAULT_PATH,
    KnownSubjectResolver,
    NandaIndexV2Resolver,
    RecordAdapter,
    RecordView,
    default_adapter,
)

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
        "--resolution-registry",
        action="append",
        default=[],
        metavar="URL",
        help=(
            "Resolution Registry base URL implementing the known-subject-resolution-02 profile "
            "(POST /resolve; repeatable). Watch ids are sent as the Subject Identity."
        ),
    )
    check.add_argument(
        "--identity-type",
        default="agent-name",
        metavar="TYPE",
        help="Subject Identity type sent to --resolution-registry sources (default: agent-name).",
    )
    check.add_argument(
        "--nanda-index",
        action="append",
        default=[],
        metavar="URL",
        help="NANDA Index v2 base URL — LEGACY two-hop resolve (repeatable). Watch ids are used as locators.",
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
    check.add_argument(
        "--sweeper-key",
        metavar="PATH",
        help="File of 64 hex chars (32-byte Ed25519 private key); emit a signed Corroboration Record per subject.",
    )
    check.add_argument("--json", action="store_true", help="Emit results as JSON.")
    return parser


def _format_text(results: list[SweepResult[RecordView]]) -> str:
    lines: list[str] = []
    for r in results:
        lines.append(f"{r.agent_id}: {r.verdict}")
        for f in r.findings:
            lines.append(f"  [{f.kind}/{f.confirmation}] {json.dumps(f.detail, sort_keys=True)}")
    if not any(r.verdict == "DIVERGENT" for r in results):
        lines.append("OK — no divergence on watched ids.")
    return "\n".join(lines)


def _load_key(path: str) -> bytes:
    with open(path, encoding="utf-8") as fh:
        return bytes.fromhex(fh.read().strip())


async def _run_check(args: argparse.Namespace) -> int:
    watch = [w for w in args.watch if w]
    http_registries = [r for r in args.registry if r]
    index_urls = [u for u in args.nanda_index if u]
    resolution_urls = [u for u in args.resolution_registry if u]
    if len(http_registries) + len(index_urls) + len(resolution_urls) < 2:
        print(
            "error: need at least two registries (--registry / --resolution-registry / --nanda-index) to corroborate",
            file=sys.stderr,
        )
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
    identity_type: str = args.identity_type

    def subject_for(agent_id: str) -> tuple[str, str]:
        return agent_id, identity_type

    registries += [KnownSubjectResolver(u, subject_for=subject_for, timeout=args.timeout) for u in resolution_urls]

    results = await check_once(registries, watch, adapter=adapter, path=args.path, timeout=args.timeout)

    if args.sweeper_key:
        from .record import sign_sweep

        key = _load_key(args.sweeper_key)
        records = sign_sweep(results, sweeper_private_key=key)
        print(json.dumps(records, sort_keys=True, indent=2))
    elif args.json:
        payload = [
            {"agent_id": r.agent_id, "verdict": r.verdict, "findings": [f.to_dict() for f in r.findings]}
            for r in results
        ]
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        print(_format_text(results))

    return EXIT_DIVERGENCE if any(r.verdict == "DIVERGENT" for r in results) else EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "check":
        return asyncio.run(_run_check(args))
    return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
