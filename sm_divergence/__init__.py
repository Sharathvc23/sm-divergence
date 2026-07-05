"""sm-divergence — catch a cheating registry by corroboration.

A registry that agents discover each other through can lie by omission (hide a
record), by tampering (serve a false endpoint), or by equivocation (different
answers to different clients). No signature on a single record can prove what a
registry chose not to serve. With two or more registries, this library asks all
of them the same questions and reports any disagreement: omission, endpoint, or
key-identity (DID) divergence.

Layout:
  - ``sm-resolver`` (dependency) — the source-agnostic kernel: ``Resolver[T]``,
    the ``View`` contract, ``diff_views``, ``Corroborator``, ``Finding``.
  - ``sm_divergence.discovery`` — the registry-integrity layer: ``RecordView``
    plus the ``HttpByIdResolver`` (NEST) and ``NandaIndexV2Resolver`` adapters.

Quick start::

    import asyncio
    from sm_divergence import check_once

    findings = asyncio.run(check_once(
        ["https://registry-a.example", "https://registry-b.example"],
        ["agent-1", "agent-2"],
    ))
    for f in findings:
        print(f.kind, f.agent_id, f.detail)
"""

from sm_resolver import OMISSION, Corroborator, Finding, OnFinding, Resolver, Status, View, ViewT, diff_views

from .detector import DivergenceDetector, check_once
from .discovery import (
    DEFAULT_PATH,
    DID,
    ENDPOINT,
    HttpByIdResolver,
    NandaIndexV2Resolver,
    RecordAdapter,
    RecordView,
    binds_by_did,
    default_adapter,
    fetch_view,
    identity_locator,
    looks_absent,
    signed_record_adapter,
    verified_did,
)
from .identity import (
    KEY,
    AliasClosureResolver,
    DescriptionReconciliation,
    DidKeyResolver,
    DidView,
    DidWebResolver,
    HttpDescriptionResolver,
    SelfDescription,
    UniversalResolverResolver,
    binds_by_key,
    build_self_description,
    corroborate_descriptions,
    did_web_url,
    identity_did,
    key_from_did_document,
    key_from_did_key,
    reconcile_descriptions,
    signed_alias_for,
    verified_descriptions,
    verify_self_description,
)

__version__ = "0.7.1"

__all__ = [
    "DEFAULT_PATH",
    "DID",
    "ENDPOINT",
    "KEY",
    "OMISSION",
    "AliasClosureResolver",
    "Corroborator",
    "DescriptionReconciliation",
    "DidKeyResolver",
    "DidView",
    "DidWebResolver",
    "DivergenceDetector",
    "Finding",
    "HttpByIdResolver",
    "HttpDescriptionResolver",
    "NandaIndexV2Resolver",
    "OnFinding",
    "RecordAdapter",
    "RecordView",
    "Resolver",
    "SelfDescription",
    "Status",
    "UniversalResolverResolver",
    "View",
    "ViewT",
    "binds_by_did",
    "binds_by_key",
    "build_self_description",
    "check_once",
    "corroborate_descriptions",
    "default_adapter",
    "diff_views",
    "did_web_url",
    "fetch_view",
    "identity_did",
    "identity_locator",
    "key_from_did_document",
    "key_from_did_key",
    "looks_absent",
    "reconcile_descriptions",
    "signed_alias_for",
    "signed_record_adapter",
    "verified_descriptions",
    "verified_did",
    "verify_self_description",
]
