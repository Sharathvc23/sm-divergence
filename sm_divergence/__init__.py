"""sm-divergence — catch a cheating registry by corroboration.

A registry that agents discover each other through can lie by omission (hide a
record), by tampering (serve a false endpoint), or by equivocation (different
answers to different clients). No signature on a single record can prove what a
registry chose not to serve. With two or more registries, this library asks all
of them the same questions and reports any disagreement: omission, endpoint, or
key-identity (DID) divergence.

This library is the reference implementation of the IETF draft *Multi-Source
Corroboration for AI Agent Discovery* (`draft-chandra-agent-registry-corroboration-00`):
the ``sm-resolver`` kernel is the claim model and diff; this package is the
signing layer (self-description, Corroboration Record) and the reference discovery
and identity layers.

Layout:
  - ``sm-resolver`` (dependency) — the source-agnostic kernel: ``Resolver[T]``,
    the ``View`` contract, ``Claim``, ``diff_claims``, ``Corroborator``,
    ``SweepResult``, ``Finding``.
  - ``sm_divergence.discovery`` — the registry-integrity layer: ``RecordView``
    plus the ``HttpByIdResolver`` (NEST) and ``NandaIndexV2Resolver`` adapters.
  - ``sm_divergence.record`` — the signed Corroboration Record (draft §9).

Quick start::

    import asyncio
    from sm_divergence import check_once

    results = asyncio.run(check_once(
        ["https://registry-a.example", "https://registry-b.example"],
        ["agent-1", "agent-2"],
    ))
    for r in results:
        print(r.agent_id, r.verdict)
        for f in r.findings:
            print(" ", f.kind, f.confirmation, f.detail)
"""

from sm_resolver import (
    CONFIRMED,
    OMISSION,
    SOURCE_EQUIVOCATION,
    SUSPECTED,
    Claim,
    Corroborator,
    Finding,
    OnFinding,
    Resolver,
    Status,
    SweepResult,
    Verdict,
    View,
    ViewT,
    diff_claims,
    diff_views,
)

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
    normalize_endpoint,
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
from .record import (
    CORROBORATION_VERSION,
    build_corroboration_record,
    sign_sweep,
    verify_corroboration_record,
)

__version__ = "0.8.0"

__all__ = [
    "CONFIRMED",
    "CORROBORATION_VERSION",
    "DEFAULT_PATH",
    "DID",
    "ENDPOINT",
    "KEY",
    "OMISSION",
    "SOURCE_EQUIVOCATION",
    "SUSPECTED",
    "AliasClosureResolver",
    "Claim",
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
    "SweepResult",
    "UniversalResolverResolver",
    "Verdict",
    "View",
    "ViewT",
    "binds_by_did",
    "binds_by_key",
    "build_corroboration_record",
    "build_self_description",
    "check_once",
    "corroborate_descriptions",
    "default_adapter",
    "diff_claims",
    "diff_views",
    "did_web_url",
    "fetch_view",
    "identity_did",
    "identity_locator",
    "key_from_did_document",
    "key_from_did_key",
    "looks_absent",
    "normalize_endpoint",
    "reconcile_descriptions",
    "sign_sweep",
    "signed_alias_for",
    "signed_record_adapter",
    "verified_descriptions",
    "verified_did",
    "verify_corroboration_record",
    "verify_self_description",
]
