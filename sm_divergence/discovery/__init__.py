"""sm-divergence discovery layer — the registry-integrity instantiation.

Supplies the discovery view type (``RecordView``) and the format resolvers
(``KnownSubjectResolver`` for any registry implementing the registry-assisted
resolution profile for known subjects — the DAWN-aligned ``POST /resolve``
binding; ``HttpByIdResolver`` for NEST-style by-id registries;
``NandaIndexV2Resolver`` for the legacy NANDA Index two-hop resolve;
``AnsV2Resolver`` for the Agent Name Service one-hop resolve), all built on the
source-agnostic core. Each resolver
is a thin adapter; adding another registry format is another file here, with no
change to the core diff.
"""

from .ans_v2 import AnsV2Resolver, identity_ansname
from .attestation import signed_record_adapter, verified_did
from .client import DEFAULT_PATH, RecordAdapter, default_adapter, fetch_view, looks_absent
from .closure import binds_by_did
from .http_by_id import HttpByIdResolver
from .index_v2 import NandaIndexV2Resolver, identity_locator
from .known_subject import (
    DEFAULT_RESOLVE_PATH as KNOWN_SUBJECT_RESOLVE_PATH,
)
from .known_subject import (
    OUTCOME_EXPIRED,
    OUTCOME_REVOKED,
    RESOLUTION_PROFILE,
    KnownSubjectResolver,
    SubjectFn,
    agent_name_subject,
    target_to_view,
)
from .views import DID, DIGEST, ENDPOINT, RecordView, normalize_endpoint

__all__ = [
    "DEFAULT_PATH",
    "DID",
    "DIGEST",
    "KNOWN_SUBJECT_RESOLVE_PATH",
    "OUTCOME_EXPIRED",
    "OUTCOME_REVOKED",
    "RESOLUTION_PROFILE",
    "ENDPOINT",
    "AnsV2Resolver",
    "HttpByIdResolver",
    "KnownSubjectResolver",
    "NandaIndexV2Resolver",
    "RecordAdapter",
    "RecordView",
    "SubjectFn",
    "agent_name_subject",
    "binds_by_did",
    "default_adapter",
    "fetch_view",
    "identity_ansname",
    "identity_locator",
    "looks_absent",
    "normalize_endpoint",
    "signed_record_adapter",
    "target_to_view",
    "verified_did",
]
