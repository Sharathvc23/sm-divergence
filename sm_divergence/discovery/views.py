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

# The canonicalization profile this module implements. RFC 3986 Section 6 names
# syntax-based normalization but leaves percent-encoding, dot-segments, empty
# versus root path, fragments and IDNA to the reader, so two conforming
# implementations can disagree — and a disagreement here is a false `endpoint`
# divergence between honest registries. This pins one profile; the test module
# `test_endpoint_canonicalization` is its vector set.
ENDPOINT_NORMALIZATION = "endpoint-normalization/0.1"

# RFC 3986 2.3. Percent-encoding one of these is equivalent to not encoding it,
# so the decoded form is canonical. Everything else stays encoded: %2F is an
# encoded slash and is NOT a path separator, and decoding it would merge two
# different endpoints.
_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _normalize_percent(text: str) -> str:
    """Uppercase percent-encoding triplets and decode unreserved characters."""
    out: list[str] = []
    i = 0
    while i < len(text):
        if text[i] == "%" and i + 2 < len(text):
            triplet = text[i : i + 3]
            try:
                char = chr(int(triplet[1:], 16))
            except ValueError:
                out.append(triplet)
            else:
                out.append(char if char in _UNRESERVED else "%" + triplet[1:].upper())
            i += 3
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 5.2.4."""
    segments: list[str] = []
    for segment in path.split("/"):
        if segment == ".":
            continue
        if segment == "..":
            if segments and segments[-1] != "":
                segments.pop()
            continue
        segments.append(segment)
    return "/".join(segments) or "/"


def normalize_endpoint(value: str | None) -> str | None:
    """Canonicalize an endpoint under `endpoint-normalization/0.1`.

    Two spellings of the same address must compare equal, and two different
    addresses must not. The rules, and why each is where it is:

    - **scheme and host** are lowercased; **the path is not.** A path may address
      distinct resources by case, so folding it would merge two endpoints.
    - **the default port for the scheme** is dropped.
    - **an empty path** becomes ``/``; **dot segments** are removed (RFC 3986
      5.2.4).
    - **percent-encoding** is uppercased, and **unreserved characters are
      decoded** (RFC 3986 2.3). Reserved ones stay encoded: ``%2F`` is an encoded
      slash, not a path separator.
    - **the query is byte-sensitive.** Its semantics belong to the server;
      reordering or dropping parameters would assert an equivalence this profile
      cannot know holds.
    - **the fragment is removed.** It is not sent to the server, so it cannot
      distinguish two endpoints as addresses.
    - **hostnames** are compared as punycode, and a trailing dot is removed.

    A non-URI or unparseable value is returned unchanged: still compared, just
    not normalized. Guessing at a shape we do not recognize would be worse than
    comparing it literally.
    """
    if value is None:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return value
    if not parts.scheme or not parts.netloc:
        return value
    scheme = parts.scheme.lower()
    try:
        host = (parts.hostname or "").rstrip(".").encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        host = (parts.hostname or "").rstrip(".").lower()
    userinfo = ""
    if parts.username is not None:
        userinfo = parts.username + (f":{parts.password}" if parts.password is not None else "") + "@"
    netloc = userinfo + host
    if parts.port is not None and str(parts.port) != _DEFAULT_PORTS.get(scheme):
        netloc += f":{parts.port}"
    path = _remove_dot_segments(_normalize_percent(parts.path or "/"))
    return urlunsplit((scheme, netloc, path, parts.query, ""))


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
