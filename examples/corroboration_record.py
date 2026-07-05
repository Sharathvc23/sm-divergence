"""Emit and verify a signed Corroboration Record (draft §9).

A sweep produces a verdict per subject; a Corroboration Record *seals* one such
result — content-addressed (``record_id`` = CORR-DIGEST) and signed by the
sweeper's ``did:key``. One record is emitted for every subject, whatever the
verdict, so an auditor can prove the checks ran (the ``AGREE`` record is the
positive attestation, not just the ``DIVERGENT`` ones). It verifies offline:
recompute the digest, check the signature against the key ``sweeper`` encodes.

Needs the ``attestation`` extra (Ed25519 / did:key / JCS).

Run:  python examples/corroboration_record.py
"""

from __future__ import annotations

import asyncio
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from sm_resolver import Claim, SweepResult

from sm_divergence import (
    RecordView,
    build_corroboration_record,
    verify_corroboration_record,
)


def raw_private() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


async def main() -> None:
    # One subject seen by two registries that agree — the AGREE result still gets
    # a record (the positive attestation that corroboration ran).
    view = RecordView(endpoint="https://acme.example/")
    result: SweepResult[RecordView] = SweepResult(
        agent_id="acme",
        verdict="AGREE",
        observed_at=1_751_600_000.0,
        staleness_window_s=60.0,
        claims=[
            Claim("reg-a", None, "present", view, 1_751_600_000.0, "present"),
            Claim("reg-b", None, "present", view, 1_751_600_000.0, "present"),
        ],
        findings=[],
    )

    sweeper_key = raw_private()  # the corroborating party's did:key private key
    record = build_corroboration_record(result, sweeper_private_key=sweeper_key)

    print(json.dumps(record, indent=2, sort_keys=True))
    print("\nverifies offline:", verify_corroboration_record(record))
    # A single flipped byte in any member breaks either the digest or the signature:
    tampered = {**record, "verdict": "DIVERGENT"}
    print("tampered verdict verifies:", verify_corroboration_record(tampered))


if __name__ == "__main__":
    asyncio.run(main())
