"""RecordView — the discovery layer's view type (an implementation of the core
``View`` contract). What a registry claims about one agent, reduced to the fields
a discovery-divergence check compares.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

# Discovery field names (also the kinds of the findings they produce).
ENDPOINT = "endpoint"
DID = "did"


@dataclass(frozen=True)
class RecordView:
    """A single registry's claim about one agent id.

    ``endpoint`` — the address the registry serves (typically unsigned; a lying
    registry can set it freely).
    ``did`` — the agent's key identity, present only when the registry served a
    record the caller could VERIFY (e.g. a valid signed attestation). An
    unverifiable identity contributes no ``did`` — one valid record plus one
    forged one is not a disagreement between two authorities.
    """

    endpoint: str | None = None
    did: str | None = None

    def comparable(self) -> Mapping[str, str | None]:
        return {ENDPOINT: self.endpoint, DID: self.did}
