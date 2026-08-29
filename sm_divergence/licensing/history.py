"""The evidence slot for prior publication.

A `scope_violation` may not be raised without evidence that the scope predates
the observation it contradicts (draft Section 9.5), and nothing in this stack
provides such evidence: establishing publication order needs a witnessed,
append-only history of what each source published and when, which the draft
places out of scope.

Leaving the *interface* undefined as well would mean a deployment that does have
one has no interoperable way to record its proof, and no verifier can check one.
So the envelope is defined and the mechanism is not.

    {
      "type": "<namespaced mechanism identifier>",
      "statement_digest": "<CORR-DIGEST of the scope bundle relied upon>",
      "proof": { ... mechanism-defined, opaque here ... }
    }

What can be checked without knowing the mechanism is the shape and the binding.
Whether the proof is *valid* is the mechanism's business, and this module does
not pretend otherwise.
"""

from __future__ import annotations

from typing import Any


def verify_history_proof(proof: Any, *, expected_digest: str) -> bool:
    """True iff the envelope is well formed and bound to ``expected_digest``.

    **This does not verify the proof.** The payload is opaque here, and a caller
    that reads True as "the scope predates the observation" has misunderstood
    what was checked. It means only that the proof names a mechanism and claims
    to be about the scope bytes in question; a mechanism-specific verifier must
    then check the payload against a log it trusts.

    The digest binding is what makes the envelope worth carrying. A proof about
    some other scope is evidence about something else, however valid it is in its
    own terms.

    ``type`` MUST be namespaced with a reverse-DNS or URI prefix. This document
    seeds no mechanisms, so every value belongs to a third party, and a bare name
    would claim a reservation that does not exist.

    Never raises.
    """
    if not isinstance(proof, dict):
        return False
    mechanism = proof.get("type")
    if not isinstance(mechanism, str) or "." not in mechanism:
        return False
    digest = proof.get("statement_digest")
    if not isinstance(digest, str) or digest != expected_digest:
        return False
    return isinstance(proof.get("proof"), dict)
