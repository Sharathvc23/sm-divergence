"""Corroborate one known subject across live sources, from the command line.

Every source is optional; give at least one. Nothing here is specific to any
deployment — the subject, the log, the resolvers and the catalog are arguments.

    # what a zone publishes, seen through two recursive resolvers
    python examples/live_sweep.py agent.example.com --zone \\
        --doh https://resolver-a.example/dns-query \\
        --doh https://resolver-b.example/dns-query

    # ...beside the registration log that sealed it, verified against its keys
    python examples/live_sweep.py agent.example.com --zone \\
        --doh https://resolver-a.example/dns-query \\
        --log https://log.example --log-keys pinned-root-keys.txt

    # one entry of a publisher's catalog
    python examples/live_sweep.py urn:air:example.com:support \\
        --catalog https://example.com

    # a directory whose identifiers change with every revision: match on the
    # display name, read the endpoint out of the inline agent card
    python examples/live_sweep.py https://agents.example.com/support \\
        --catalog https://directory.example --follow-nested \\
        --catalog-match displayName --catalog-inline JSONRPC

`--zone` reads the SVCB rows at the subject, or the `v=ans1` TXT rows at
`_ans.{subject}` when it publishes no SVCB row. Each `--doh` URL is one recursive resolver, queried with DNS
over HTTPS, and one vantage; without any, the system resolver is used.

`--log` reads the log's badge for the subject, located through the subject's
badge TXT row. With `--log-keys FILE` the claim is read only from the log's
signed receipt and status token, verified against the keys in FILE. With
`--log-keys fetch` the keys are fetched from the log itself — that shows the log
is self-consistent, not that it is the log you meant; pin the keys for anything
that matters.

Needs the `dns` extra, and the `cose` extra for `--log-keys`.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any
from urllib.parse import urlsplit

import httpx
from sm_resolver import Corroborator

from sm_divergence.discovery import (
    AnsLogResolver,
    CatalogResolver,
    DnspythonQuery,
    DnsZoneResolver,
    DohQuery,
    a2a_interface_url,
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("subject", help="the known subject: an FQDN, or a catalog entry identifier")
    parser.add_argument("--zone", action="store_true", help="read the subject's DNS zone")
    parser.add_argument(
        "--doh", action="append", default=[], metavar="URL", help="a DNS-over-HTTPS resolver (repeatable)"
    )
    parser.add_argument("--protocol", help="agent protocol to select (e.g. a2a, mcp)")
    parser.add_argument("--target", choices=["descriptor", "service"], default="descriptor")
    parser.add_argument("--log", metavar="URL", help="a registration log's base URL")
    parser.add_argument("--log-keys", metavar="FILE|fetch", help="verify against these keys")
    parser.add_argument("--catalog", metavar="URL", help="a publisher's origin")
    parser.add_argument("--catalog-id", metavar="ID", help="entry identifier, if not the subject itself")
    parser.add_argument("--artifact-type", help="catalog entry media type to select")
    parser.add_argument("--catalog-path", action="append", metavar="PATH", help="catalog path to try (repeatable)")
    parser.add_argument("--catalog-match", default="identifier", metavar="MEMBER", help="entry member to match on")
    parser.add_argument(
        "--catalog-inline",
        metavar="BINDING",
        help="read an inline agent card's interface for this binding ('' for any)",
    )
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--follow-nested", action="store_true")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args(argv)
    if not (args.zone or args.log or args.catalog):
        parser.error("give at least one source: --zone, --log or --catalog")
    return args


async def root_keys(args: argparse.Namespace) -> str | None:
    if not args.log_keys:
        return None
    if args.log_keys != "fetch":
        with open(args.log_keys, encoding="utf-8") as handle:
            return handle.read()
    async with httpx.AsyncClient() as client:
        resp = await client.get(args.log.rstrip("/") + "/root-keys", timeout=args.timeout)
        resp.raise_for_status()
    print("note: verification keys were fetched from the log being read (self-consistency only)\n")
    return resp.text


async def build_sources(args: argparse.Namespace) -> list[Any]:
    queries: list[tuple[str | None, Any]] = [
        (urlsplit(url).hostname, DohQuery(url, timeout=args.timeout)) for url in args.doh
    ] or [(None, DnspythonQuery(timeout=args.timeout))]

    sources: list[Any] = []
    if args.zone:
        for vantage, query in queries:
            sources.append(
                DnsZoneResolver(
                    query=query,
                    protocol=args.protocol,
                    target=args.target,
                    timeout=args.timeout,
                    label="zone",
                    vantage=vantage,
                )
            )
    if args.log:
        sources.append(
            AnsLogResolver(
                args.log,
                protocol=args.protocol,
                target=args.target,
                root_keys=await root_keys(args),
                badge_query=queries[0][1],
                timeout=args.timeout,
                label="log",
            )
        )
    if args.catalog:
        identifier = args.catalog_id or args.subject
        sources.append(
            CatalogResolver(
                args.catalog,
                identifier_for=lambda _subject: identifier,
                artifact_type=args.artifact_type,
                match_on=args.catalog_match,
                inline_endpoint=(
                    a2a_interface_url(args.catalog_inline or None) if args.catalog_inline is not None else None
                ),
                **({"catalog_paths": args.catalog_path} if args.catalog_path else {}),
                follow_redirects=args.follow_redirects,
                follow_nested=args.follow_nested,
                timeout=args.timeout,
                label="catalog",
            )
        )
    return sources


async def main(argv: list[str]) -> int:
    args = parse_args(argv)
    sources = await build_sources(args)
    (result,) = await Corroborator(sources).check([args.subject])

    print(f"{result.agent_id}: {result.verdict}")
    for claim in result.claims:
        where = f"{claim.source}@{claim.vantage}" if claim.vantage else claim.source
        if claim.view is not None:
            shown = {key: value for key, value in claim.view.comparable().items() if value is not None}
            print(f"  claim   [{where}] {claim.status}  {shown}")
        else:
            print(f"  claim   [{where}] {claim.status}  ({claim.outcome})")
    for finding in result.findings:
        print(f"  finding {finding.kind:20} {finding.confirmation}  {finding.detail}")
    if not result.findings:
        print("  no findings")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
