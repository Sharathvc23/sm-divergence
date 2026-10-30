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

from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _dist_version

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

from ._signing import ALG_ED25519
from .detector import DivergenceDetector, check_once
from .discovery import (
    DEFAULT_PATH,
    DID,
    DIGEST,
    ENDPOINT,
    AnsV2Resolver,
    HttpByIdResolver,
    KnownSubjectResolver,
    NandaIndexV2Resolver,
    RecordAdapter,
    RecordView,
    binds_by_did,
    default_adapter,
    fetch_view,
    identity_ansname,
    identity_locator,
    looks_absent,
    normalize_endpoint,
    signed_record_adapter,
    target_to_view,
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
    OperatorDescription,
    SelfDescription,
    UniversalResolverResolver,
    binds_by_key,
    build_operator_description,
    build_self_description,
    corroborate_descriptions,
    did_web_url,
    identity_did,
    key_from_did_document,
    key_from_did_key,
    reconcile_descriptions,
    signed_alias_for,
    verified_descriptions,
    verify_operator_description,
    verify_self_description,
)
from .licensing import (
    AnswerScope,
    build_answer_scope,
    scope_evidence,
    verify_answer_scope,
    verify_history_proof,
)
from .record import (
    ACCEPTED_RECORD_VERSIONS,
    CORROBORATION_VERSION,
    build_corroboration_record,
    sign_sweep,
    verify_corroboration_record,
)

# Derived from installed distribution metadata, never hand-maintained. A literal
# here is a second copy of pyproject's ``version`` with nothing comparing them —
# the shape that shipped sm-provision 0.1.0 reporting "0.0.1" and sm-authority
# 0.1.0 reporting the same wrong value from the same template. Correct today is
# not the test; it drifts at the next bump.
try:  # pragma: no cover - trivial branch, both sides asserted in tests
    __version__ = _dist_version("sm-divergence")
except _PackageNotFoundError:  # running from a source tree, not installed
    __version__ = "0.0.0.dev0"

__all__ = [
    "CONFIRMED",
    "ACCEPTED_RECORD_VERSIONS",
    "ALG_ED25519",
    "CORROBORATION_VERSION",
    "DEFAULT_PATH",
    "DID",
    "DIGEST",
    "ENDPOINT",
    "KEY",
    "OMISSION",
    "SOURCE_EQUIVOCATION",
    "SUSPECTED",
    "AliasClosureResolver",
    "AnsV2Resolver",
    "Claim",
    "Corroborator",
    "DescriptionReconciliation",
    "DidKeyResolver",
    "DidView",
    "DidWebResolver",
    "DivergenceDetector",
    "Finding",
    "HttpByIdResolver",
    "KnownSubjectResolver",
    "HttpDescriptionResolver",
    "NandaIndexV2Resolver",
    "OnFinding",
    "RecordAdapter",
    "RecordView",
    "Resolver",
    "AnswerScope",
    "OperatorDescription",
    "SelfDescription",
    "build_answer_scope",
    "scope_evidence",
    "verify_history_proof",
    "build_operator_description",
    "verify_answer_scope",
    "verify_operator_description",
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
    "identity_ansname",
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
    "target_to_view",
    "verified_descriptions",
    "verified_did",
    "verify_corroboration_record",
    "verify_self_description",
]
