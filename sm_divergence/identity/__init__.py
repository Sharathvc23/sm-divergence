"""sm-divergence identity layer — key-consistency across DID methods.

The second layer on the source-agnostic core (after discovery): it resolves an
agent's identity through several DID methods and corroborates the one field that
must agree — the verification key. A ``did:web`` (or a Universal Resolver) that
serves a different key than the agent's self-certifying ``did:key`` root is a
``key`` divergence: a hijacked domain, a stale mirror, or a lying resolver.

Same shape as discovery: a ``DidView`` (implements the core ``View``) plus thin
per-method ``Resolver`` adapters, corroborated by the core ``Corroborator``.
"""

from .closure import AliasClosureResolver, binds_by_key
from .description_layer import (
    DescriptionReconciliation,
    HttpDescriptionResolver,
    corroborate_descriptions,
    reconcile_descriptions,
)
from .didkey import DidKeyResolver, key_from_did_key
from .didweb import DidWebResolver, did_web_url, key_from_did_document
from .operator import (
    OperatorDescription,
    build_operator_description,
    verify_operator_description,
)
from .selfdesc import (
    SelfDescription,
    build_self_description,
    signed_alias_for,
    verified_descriptions,
    verify_self_description,
)
from .universal import UniversalResolverResolver
from .views import KEY, DidFor, DidView, identity_did

__all__ = [
    "KEY",
    "AliasClosureResolver",
    "DescriptionReconciliation",
    "DidFor",
    "DidKeyResolver",
    "DidView",
    "DidWebResolver",
    "HttpDescriptionResolver",
    "OperatorDescription",
    "SelfDescription",
    "build_operator_description",
    "verify_operator_description",
    "UniversalResolverResolver",
    "binds_by_key",
    "build_self_description",
    "corroborate_descriptions",
    "did_web_url",
    "identity_did",
    "key_from_did_document",
    "key_from_did_key",
    "reconcile_descriptions",
    "signed_alias_for",
    "verified_descriptions",
    "verify_self_description",
]
