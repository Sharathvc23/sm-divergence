"""sm-divergence discovery layer — the registry-integrity instantiation.

Supplies the discovery view type (``RecordView``) and the format resolvers
(``HttpByIdResolver`` for NEST-style by-id registries, ``NandaIndexV2Resolver``
for the NANDA Index two-hop resolve), all built on the source-agnostic core.
Each resolver is a thin adapter; adding another registry format is another file
here, with no change to the core diff.
"""

from .attestation import signed_record_adapter, verified_did
from .client import DEFAULT_PATH, RecordAdapter, default_adapter, fetch_view, looks_absent
from .closure import binds_by_did
from .http_by_id import HttpByIdResolver
from .index_v2 import NandaIndexV2Resolver, identity_locator
from .views import DID, ENDPOINT, RecordView

__all__ = [
    "DEFAULT_PATH",
    "DID",
    "ENDPOINT",
    "HttpByIdResolver",
    "NandaIndexV2Resolver",
    "RecordAdapter",
    "RecordView",
    "binds_by_did",
    "default_adapter",
    "fetch_view",
    "identity_locator",
    "looks_absent",
    "signed_record_adapter",
    "verified_did",
]
