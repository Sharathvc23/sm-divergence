"""Answer Scope — a registry declaring, in advance, which fields it varies.

A corroborator that flags every difference as a lie fires on normal operation: a
registry may serve a region-specific endpoint for data-residency reasons. An
Answer Scope is the operator saying so *before* it is observed, so that a
divergence can be recorded as one the operator had already described.

It declares an AXIS, never a mapping. "``endpoint`` varies by ``region``" is
checkable — a verifier can observe from another region and compare. "EU callers
get X" would be a promise about values, and a promise by the party doing the
varying adds a label to a finding without adding any way to test it.

Bundle shape (flat; the signature is a member, over the JCS of every other
member)::

    {
      "version": "answer-scope/0.1",
      "subject": "did:key:z6Mk…",
      "label": "https://registry.example",
      "seq": 3,
      "scopes": [ {"field": "endpoint", "vantage_class": "region"} ],
      "signature": "<base64 Ed25519 over the JCS of all other members>"
    }

An empty ``scopes`` list is meaningful and is NOT the same as publishing nothing:
it is the operator positively asserting that it does not vary. Silence is
ambiguous between "does not vary" and "has never heard of this"; an empty scope
resolves that.

Requires the ``attestation`` extra (Ed25519 / did:key / JCS).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .. import _signing

ANSWER_SCOPE_VERSION = "answer-scope/0.1"

# SPEC.md §3a.1 grammar, reused: a class name is a lowercase kebab token.
_TOKEN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

# SPEC.md §3a.2 occupiability: a class must be one a third party can construct
# and observe from. Seeded set; a deployment may widen it deliberately, never by
# accident, which is why it is a parameter and not a module global.
OCCUPIABLE_CLASSES: frozenset[str] = frozenset({"region", "asn"})

# SPEC.md §3a.2 cardinality. A scope that names every field declares nothing
# useful; the cap makes "declare the maximal envelope once" fail loudly.
MAX_SCOPES = 16


@dataclass(frozen=True)
class AnswerScope:
    """A verified Answer Scope: which fields the operator declared it varies, and
    along which vantage class, at a monotonic ``seq`` (higher supersedes lower)."""

    subject: str
    label: str
    seq: int
    scopes: tuple[tuple[str, str], ...]

    def varies(self, field: str) -> str | None:
        """The vantage class ``field`` was declared to vary along, or None if the
        operator did not declare it. None means the field is compared exactly as
        an undeclared field is."""
        for name, vantage_class in self.scopes:
            if name == field:
                return vantage_class
        return None

    @property
    def declares_no_variation(self) -> bool:
        """True iff the operator positively asserted it does not vary — an empty
        scope list. Distinct from having published nothing at all."""
        return not self.scopes


def _descriptor(subject: str, label: str, seq: int, scopes: list[dict[str, str]]) -> dict[str, Any]:
    return {
        "version": ANSWER_SCOPE_VERSION,
        "subject": subject,
        "label": label,
        "seq": seq,
        "scopes": scopes,
    }


def build_answer_scope(
    label: str,
    scopes: list[dict[str, str]],
    private_key: bytes,
    *,
    seq: int,
) -> dict[str, Any]:
    """A signed Answer Scope for the operator holding ``private_key`` (32 raw
    Ed25519 bytes). ``scopes`` is a list of ``{"field", "vantage_class"}``; an
    empty list asserts no variation. Bump ``seq`` on every re-issue."""
    subject = _signing.did_key_from_pubkey(_signing.public_from_private(private_key))
    bundle = _descriptor(subject, label, seq, [dict(s) for s in scopes])
    bundle["signature"] = _signing.sign(private_key, _signing.canonical(bundle))
    return bundle


def _parse_scopes(value: Any, occupiable: frozenset[str]) -> tuple[tuple[str, str], ...] | None:
    if not isinstance(value, list) or len(value) > MAX_SCOPES:
        return None
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"field", "vantage_class"}:
            return None
        field = entry["field"]
        vantage_class = entry["vantage_class"]
        if not isinstance(field, str) or not isinstance(vantage_class, str):
            return None
        if not _TOKEN.match(field) or not _TOKEN.match(vantage_class):
            return None
        if vantage_class not in occupiable:
            return None
        if field in seen:
            return None
        seen.add(field)
        out.append((field, vantage_class))
    return tuple(out)


def verify_answer_scope(
    bundle: Any,
    *,
    served_from: str,
    occupiable: frozenset[str] = OCCUPIABLE_CLASSES,
) -> AnswerScope | None:
    """Verify a bundle's signature against the key its ``subject`` encodes, that
    it names ``served_from``, and that every scope is well-formed.

    Rejects, in addition to a bad signature:

    - a ``label`` that is not ``served_from`` (exact equality, no URL
      normalisation) — serving it at the label is what proves control of it
    - a ``vantage_class`` outside ``occupiable`` — a class a verifier cannot go
      and observe from cannot be checked, so accepting one would mean reporting
      the operator's own assertion back as evidence
    - a wildcard or malformed token in either position — a scope that matches
      everything is the permissive form that becomes the attack surface
    - the same ``field`` declared twice — overlapping scopes let the operator
      pick whichever applies after the fact
    - more than ``MAX_SCOPES`` entries

    Returns the ``AnswerScope`` or None. Never raises.
    """
    if not isinstance(bundle, dict):
        return None
    signature = bundle.get("signature")
    if not isinstance(signature, str) or not signature:
        return None
    if bundle.get("version") != ANSWER_SCOPE_VERSION:
        return None
    subject = bundle.get("subject")
    label = bundle.get("label")
    seq = bundle.get("seq")
    if not isinstance(subject, str) or not isinstance(label, str):
        return None
    if not isinstance(seq, int) or isinstance(seq, bool):
        return None
    scopes = _parse_scopes(bundle.get("scopes"), occupiable)
    if scopes is None:
        return None

    pub = _signing.pubkey_from_did_key(subject)
    if pub is None:
        return None
    signed = {k: v for k, v in bundle.items() if k != "signature"}
    if not _signing.verify(pub, _signing.canonical(signed), signature):
        return None
    if label != served_from:
        return None
    return AnswerScope(subject=subject, label=label, seq=seq, scopes=scopes)


def scope_evidence(scopes: Mapping[str, AnswerScope]) -> list[dict[str, Any]]:
    """The record's ``answer_scopes``: what a verifier needs to re-derive a
    declared finding.

    ``declared: true`` with a sequence number says a scope was *allegedly*
    matched. It does not say which ``{field, vantage_class}`` rule was matched,
    nor which bytes sequence 7 refers to. A third party holding only the record
    cannot reproduce the decision, which the record format otherwise claims
    throughout: verifiable from recorded bytes.

    Each entry carries ``label``, ``subject``, ``seq``, ``scope_digest`` and
    ``scopes``. The digest is what makes this evidence rather than a
    restatement — a verifier already holding a bundle can tell whether it is the
    one that was used. The scope contents are carried too because a verifier that
    does *not* hold the bundle would otherwise have to fetch it, and a fetch is
    exactly what offline verification is meant to avoid.

    Ordered by label, so the record is deterministic.
    """
    out: list[dict[str, Any]] = []
    for label in sorted(scopes):
        scope = scopes[label]
        body = {
            "version": ANSWER_SCOPE_VERSION,
            "subject": scope.subject,
            "label": scope.label,
            "seq": scope.seq,
            "scopes": [{"field": f, "vantage_class": c} for f, c in scope.scopes],
        }
        out.append(
            {
                "label": scope.label,
                "subject": scope.subject,
                "seq": scope.seq,
                "scope_digest": _signing.corr_digest(body),
                "scopes": body["scopes"],
            }
        )
    return out
