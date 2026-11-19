"""sm-divergence discovery layer — the registry-integrity instantiation.

Supplies the discovery view type (``RecordView``) and the format resolvers
(``KnownSubjectResolver`` for any registry implementing the registry-assisted
resolution profile for known subjects — the DAWN-aligned ``POST /resolve``
binding; ``HttpByIdResolver`` for NEST-style by-id registries;
``NandaIndexV2Resolver`` for the legacy NANDA Index two-hop resolve;
``AnsV2Resolver`` for the Agent Name Service one-hop resolve;
``AnsLogResolver`` for its public transparency-log badge;
``DnsSvcbResolver`` / ``DnsTxtResolver`` for a DNS zone as a source), all built
on the source-agnostic core. Each resolver
is a thin adapter; adding another registry format is another file here, with no
change to the core diff.
"""

from .ans_log import OUTCOME_NO_BADGE, AnsLogResolver, split_badge_url
from .ans_v2 import AnsV2Resolver, ans_agent_adapter, identity_ansname
from .attestation import signed_record_adapter, verified_did
from .client import DEFAULT_PATH, RecordAdapter, default_adapter, fetch_view, looks_absent
from .closure import binds_by_did
from .dns_records import (
    DEFAULT_KEY_MAP,
    OUTCOME_AMBIGUOUS_RRSET,
    DnsAnswer,
    DnspythonQuery,
    DnsQuery,
    DnsSvcbResolver,
    DnsTxtResolver,
    SvcbRow,
    SvcParamKeyMap,
    identity_owner,
    normalize_owner,
    reduce_ans_txt,
    reduce_svcb_rows,
    svcb_rows_from_text,
    txt_rows_from_text,
)
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
from .views import (
    DID,
    DIGEST,
    DIGEST_NORMALIZATION,
    ENDPOINT,
    ENDPOINT_NORMALIZATION,
    RecordView,
    normalize_digest,
    normalize_endpoint,
)

__all__ = [
    "AnsLogResolver",
    "AnsV2Resolver",
    "DEFAULT_KEY_MAP",
    "DEFAULT_PATH",
    "DID",
    "DIGEST",
    "DIGEST_NORMALIZATION",
    "DnsAnswer",
    "DnsQuery",
    "DnsSvcbResolver",
    "DnsTxtResolver",
    "DnspythonQuery",
    "ENDPOINT",
    "ENDPOINT_NORMALIZATION",
    "HttpByIdResolver",
    "KNOWN_SUBJECT_RESOLVE_PATH",
    "KnownSubjectResolver",
    "NandaIndexV2Resolver",
    "OUTCOME_AMBIGUOUS_RRSET",
    "OUTCOME_EXPIRED",
    "OUTCOME_NO_BADGE",
    "OUTCOME_REVOKED",
    "RESOLUTION_PROFILE",
    "RecordAdapter",
    "RecordView",
    "SubjectFn",
    "SvcParamKeyMap",
    "SvcbRow",
    "agent_name_subject",
    "ans_agent_adapter",
    "binds_by_did",
    "default_adapter",
    "fetch_view",
    "identity_ansname",
    "identity_locator",
    "identity_owner",
    "looks_absent",
    "normalize_digest",
    "normalize_endpoint",
    "normalize_owner",
    "reduce_ans_txt",
    "reduce_svcb_rows",
    "signed_record_adapter",
    "split_badge_url",
    "svcb_rows_from_text",
    "target_to_view",
    "txt_rows_from_text",
    "verified_did",
]
