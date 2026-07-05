"""Discovery bind-back predicate for alias closure (see
``sm_divergence.identity.AliasClosureResolver``).
"""

from __future__ import annotations

from .views import RecordView


def binds_by_did(view: RecordView, expected_did: str) -> bool:
    """Discovery bind-back: the record's VERIFIED did must equal the expected
    ``did:key``. A record with no verified did (no valid attestation) cannot bind
    back, so it contributes no claim — you cannot safely follow a claimed
    discovery alias without a record that proves it is the same agent."""
    return view.did is not None and view.did == expected_did
