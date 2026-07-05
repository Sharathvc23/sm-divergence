"""RecordView — the discovery layer's view type (an implementation of the core
``View`` contract). What a registry claims about one agent, reduced to the fields
a discovery-divergence check compares.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

# Discovery field names (also the kinds of the findings they produce).
ENDPOINT = "endpoint"
DID = "did"

_DEFAULT_PORTS = {"http": "80", "https": "443", "ws": "80", "wss": "443"}


def normalize_endpoint(value: str | None) -> str | None:
    """RFC 3986 §6 syntax-based normalization, so two spellings of the same
    endpoint compare equal (draft §5): lowercase scheme and host, drop the default
    port for the scheme, and treat an empty path as ``/``. Non-URI or unparseable
    values are returned unchanged (still compared, just not normalized)."""
    if value is None:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.netloc:
        return value
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    userinfo = ""
    if parts.username is not None:
        userinfo = parts.username + (f":{parts.password}" if parts.password is not None else "") + "@"
    netloc = userinfo + host
    if parts.port is not None and str(parts.port) != _DEFAULT_PORTS.get(scheme):
        netloc += f":{parts.port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, parts.fragment))


@dataclass(frozen=True)
class RecordView:
    """A single registry's claim about one agent id.

    ``endpoint`` — the address the registry serves (typically unsigned; a lying
    registry can set it freely). Normalized per RFC 3986 in ``comparable()`` so
    two spellings of the same address are not a false divergence.
    ``did`` — the agent's key identity, present only when the registry served a
    record the caller could VERIFY (e.g. a valid signed attestation). An
    unverifiable identity contributes no ``did`` — one valid record plus one
    forged one is not a disagreement between two authorities.
    """

    endpoint: str | None = None
    did: str | None = None

    def comparable(self) -> Mapping[str, str | None]:
        return {ENDPOINT: normalize_endpoint(self.endpoint), DID: self.did}
