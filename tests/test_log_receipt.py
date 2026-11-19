"""Verifying a log's signed receipt and status token, and the resolver's verified mode.

The Merkle walk is checked against an independent construction: the tree and its
audit paths are built here from the recursive definitions (RFC 9162 sections
2.1.1 and 2.1.3.1), and the iterative verifier must reach the same root for
every leaf of every tree size tried. Signed fixtures are produced with a key
made in the test; every way of tampering with one must be refused, and refused
for the right reason.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import cbor2
import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from sm_resolver import OUTCOME_REFUSED, OUTCOME_UNPARSEABLE, OUTCOME_UNREACHABLE, OUTCOME_UNVERIFIABLE, Status

from sm_divergence.discovery import (
    OUTCOME_EXPIRED,
    OUTCOME_REVOKED,
    AnsLogResolver,
    ReceiptError,
    RecordView,
    parse_root_keys,
    verify_receipt,
    verify_status_token,
)
from sm_divergence.discovery.log_receipt import key_id, leaf_hash, node_hash, root_from_inclusion_proof

LOG = "https://log.example"
ORIGIN = "log.example"
AGENT_ID = "3f0c1a52-6b0e-4d57-9a44-2f6f0d1e7c11"
FQDN = "agent.example.com"
CARD = "https://agent.example.com/agent-card.json"
NOW = 1_800_000_000


# --- an independent Merkle tree, from the recursive definitions ---------------


def split(n: int) -> int:
    """The largest power of two smaller than ``n``."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: list[bytes]) -> bytes:
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = split(len(leaves))
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def audit_path(m: int, leaves: list[bytes]) -> list[bytes]:
    if len(leaves) == 1:
        return []
    k = split(len(leaves))
    if m < k:
        return [*audit_path(m, leaves[:k]), mth(leaves[k:])]
    return [*audit_path(m - k, leaves[k:]), mth(leaves[:k])]


def entries(n: int) -> list[bytes]:
    return [f"entry-{i}".encode() for i in range(n)]


def test_empty_leaf_hash_is_the_published_constant() -> None:
    assert leaf_hash(b"").hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert node_hash(b"\x00" * 32, b"\x11" * 32) == hashlib.sha256(b"\x01" + b"\x00" * 32 + b"\x11" * 32).digest()


def test_every_leaf_of_every_tree_size_walks_to_the_root() -> None:
    for size in range(1, 70):
        leaves = entries(size)
        root = mth(leaves)
        for index in range(size):
            path = audit_path(index, leaves)
            assert root_from_inclusion_proof(leaf_hash(leaves[index]), index, size, path) == root


def test_a_proof_for_one_position_does_not_verify_at_another() -> None:
    leaves = entries(13)
    root = mth(leaves)
    path = audit_path(5, leaves)
    for index in range(13):
        if index == 5:
            continue
        try:
            assert root_from_inclusion_proof(leaf_hash(leaves[5]), index, 13, path) != root
        except ReceiptError:
            pass  # a path of the wrong length for that position is also a refusal
    assert root_from_inclusion_proof(leaf_hash(leaves[6]), 5, 13, path) != root


@pytest.mark.parametrize(
    ("index", "size", "path", "message"),
    [
        (0, 0, [], "empty tree"),
        (4, 4, [], "outside the tree"),
        (-1, 4, [], "outside the tree"),
        (0, 4, [b"\x00" * 32], "too short"),
        (0, 4, [b"\x00" * 32] * 3, "too long"),
        (0, 1, [b"\x00" * 32], "too long"),
        (0, 4, [b"\x00" * 31, b"\x00" * 32], "wrong size"),
    ],
)
def test_malformed_proofs_are_refused(index: int, size: int, path: list[bytes], message: str) -> None:
    with pytest.raises(ReceiptError, match=message):
        root_from_inclusion_proof(b"\x00" * 32, index, size, path)


def test_leaf_hash_of_the_wrong_size_is_refused() -> None:
    with pytest.raises(ReceiptError, match="leaf hash"):
        root_from_inclusion_proof(b"\x00" * 31, 0, 1, [])


# --- keys ---------------------------------------------------------------------


def new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def spki(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def key_line(key: ec.EllipticCurvePrivateKey, *, keyhash: str | None = None, kind: int = 2) -> str:
    kid = keyhash if keyhash is not None else hashlib.sha256(spki(key)).digest()[:4].hex()
    return f"{ORIGIN}+{kid}+{base64.b64encode(bytes([kind]) + spki(key)).decode()}"


def pem(key: Any) -> str:
    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


KEY = new_key()
KID = hashlib.sha256(spki(KEY)).digest()[:4]


def test_key_line_is_read_and_indexed_by_kid() -> None:
    keys = parse_root_keys(key_line(KEY) + "\n\n")
    assert list(keys) == [KID.hex()]
    assert key_id(keys[KID.hex()]) == KID.hex()


def test_several_lines_and_iterables_of_lines() -> None:
    other = new_key()
    text = key_line(KEY) + "\n" + key_line(other) + "\n"
    assert len(parse_root_keys(text)) == 2
    assert parse_root_keys([key_line(KEY), "", key_line(other)]).keys() == parse_root_keys(text).keys()


def test_pem_keys_are_read() -> None:
    other = new_key()
    assert list(parse_root_keys(pem(KEY))) == [KID.hex()]
    assert len(parse_root_keys(pem(KEY) + pem(other))) == 2
    assert len(parse_root_keys([pem(KEY), key_line(other)])) == 2


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("", "no verification key"),
        ("\n  \n", "no verification key"),
        ("just-one-field", "not <origin>"),
        (f"{ORIGIN}+abcd1234+not base64!", "not base64"),
        (f"{ORIGIN}+abcd1234+{base64.b64encode(b'x').decode()}", "key type"),
        (f"{ORIGIN}+abcd1234+{base64.b64encode(bytes([2]) + b'not-a-key').decode()}", "readable SPKI"),
        ("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", "readable PEM"),
    ],
)
def test_unusable_keys_are_refused(text: str, message: str) -> None:
    with pytest.raises(ReceiptError, match=message):
        parse_root_keys(text)


def test_a_line_whose_key_hash_is_not_its_keys_is_refused() -> None:
    with pytest.raises(ReceiptError, match="key hash"):
        parse_root_keys(key_line(KEY, keyhash="00000000"))
    with pytest.raises(ReceiptError, match="key type"):
        parse_root_keys(key_line(KEY, kind=1))


def test_a_key_on_another_curve_is_refused() -> None:
    p384 = ec.generate_private_key(ec.SECP384R1())
    with pytest.raises(ReceiptError, match="P-256"):
        parse_root_keys(pem(p384))


# --- building signed fixtures -------------------------------------------------


def sign(key: ec.EllipticCurvePrivateKey, protected: bytes, payload: bytes) -> bytes:
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
    r, s = utils.decode_dss_signature(key.sign(to_sign, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def event(agent_id: str = AGENT_ID, host: str = FQDN, records: Any = None) -> dict[str, Any]:
    return {
        "ansId": agent_id,
        "ansName": f"ans://v1.0.0.{host}",
        "eventType": "AGENT_REGISTERED",
        "agent": {"host": host, "name": "Agent", "version": "v1.0.0"},
        "attestations": {
            "dnsRecordsProvisioned": records
            if records is not None
            else {f"_ans.{host}": f"v=ans1; version=1.0.0; url={CARD}"},
            "domainValidation": "ACME-DNS-01",
        },
    }


def envelope(ev: dict[str, Any] | None = None) -> bytes:
    doc = {
        "payload": {"logId": "log-1", "producer": {"event": ev or event(), "keyId": "ra-1", "signature": "x..y"}},
        "schemaVersion": "V1",
        "signature": "x..y",
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def receipt(
    payload: bytes | None = None,
    *,
    key: ec.EllipticCurvePrivateKey = KEY,
    index: int = 4,
    size: int = 11,
    protected: dict[int, Any] | None = None,
    proof: dict[int, Any] | None = None,
    tagged: bool = True,
    attach: bool = True,
    signature: bytes | None = None,
) -> bytes:
    """A receipt for ``payload`` at ``index`` of a ``size``-leaf tree."""
    body = payload if payload is not None else envelope()
    leaves = entries(size)
    leaves[index] = body
    header = {1: -7, 4: hashlib.sha256(spki(key)).digest()[:4], 395: 1, 15: {1: ORIGIN, 6: NOW - 100}}
    if protected is not None:
        header = {k: v for k, v in {**header, **protected}.items() if v is not None}
    protected_bytes = cbor2.dumps(header)
    vdp = {-1: size, -2: index, -3: audit_path(index, leaves), -4: mth(leaves)}
    if proof is not None:
        vdp = {k: v for k, v in {**vdp, **proof}.items() if v is not None}
    sig = signature if signature is not None else sign(key, protected_bytes, body)
    array = [protected_bytes, {396: vdp}, body if attach else None, sig]
    return cbor2.dumps(cbor2.CBORTag(18, array) if tagged else array)


def status_token(
    *,
    key: ec.EllipticCurvePrivateKey = KEY,
    agent_id: str = AGENT_ID,
    status: str = "ACTIVE",
    issued_at: int = NOW - 10,
    expires_at: int = NOW + 3600,
    claims: dict[int, Any] | None = None,
) -> bytes:
    body = {1: agent_id, 2: status, 3: issued_at, 4: expires_at, 5: f"ans://v1.0.0.{FQDN}"}
    if claims is not None:
        body = {k: v for k, v in {**body, **claims}.items() if v is not None}
    payload = cbor2.dumps(body)
    protected = cbor2.dumps({3: "application/ans-status-token+cbor", 1: -7, 4: hashlib.sha256(spki(key)).digest()[:4]})
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, sign(key, protected, payload)]))


KEYS = parse_root_keys(key_line(KEY))


# --- receipt ------------------------------------------------------------------


def test_receipt_verifies_and_returns_the_sealed_payload() -> None:
    verified = verify_receipt(receipt(), KEYS)
    assert verified.payload == envelope()
    assert (verified.tree_size, verified.leaf_index, verified.kid) == (11, 4, KID.hex())
    assert (verified.issuer, verified.issued_at) == (ORIGIN, NOW - 100)
    assert len(verified.root_hash) == 32


def test_keys_may_be_given_in_any_form_parse_root_keys_accepts() -> None:
    assert verify_receipt(receipt(), key_line(KEY)).kid == KID.hex()
    assert verify_receipt(receipt(), [pem(KEY)]).kid == KID.hex()


def test_untagged_array_and_every_tree_position_are_accepted() -> None:
    assert verify_receipt(receipt(tagged=False), KEYS).payload == envelope()
    for size in (1, 2, 3, 8, 9):
        for index in range(size):
            assert verify_receipt(receipt(index=index, size=size), KEYS).leaf_index == index


def flip(data: bytes, offset: int) -> bytes:
    return data[:offset] + bytes([data[offset] ^ 1]) + data[offset + 1 :]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xff\xff", "not CBOR"),
        (cbor2.dumps({"a": 1}), "four-element array"),
        (cbor2.dumps(cbor2.CBORTag(17, [b"", {}, b"x", b""])), "wrong tag"),
        (cbor2.dumps([b"", {}, b"x"]), "four-element array"),
        (cbor2.dumps(["text", {}, b"x", b""]), "byte string"),
        (cbor2.dumps([b"\xff", {}, b"x", b""]), "protected header is not CBOR"),
        (cbor2.dumps([cbor2.dumps([1]), {}, b"x", b""]), "protected header is not a map"),
        (cbor2.dumps([cbor2.dumps({1: -7}), [], b"x", b""]), "unprotected header"),
        (receipt(attach=False), "no attached payload"),
        (receipt(protected={1: -35}), "not ES256"),
        (receipt(protected={1: None}), "not ES256"),
        (receipt(protected={395: 2}), "RFC 9162"),
        (receipt(protected={4: None}), "no usable kid"),
        (receipt(protected={4: b"\x00" * 8}), "no usable kid"),
        (receipt(key=new_key()), "not trusted"),
        (receipt(signature=b"\x00" * 63), "wrong size"),
        (receipt(signature=b"\x01" * 64), "does not verify"),
        (receipt(proof={-4: b"\x00" * 32}), "not included"),
        (receipt(proof={-4: b"\x00" * 31}), "root has the wrong size"),
        (receipt(proof={-2: 5}), "not included"),
        (receipt(proof={-1: 5}), "not included|too short|too long"),
        (receipt(proof={-3: []}), "too short"),
        (receipt(proof={-3: "x"}), "not a list"),
        (receipt(proof={-3: [1, 2]}), "not a list"),
        (receipt(proof={-1: -1}), "non-negative"),
        (receipt(proof={-2: True}), "non-negative"),
        (receipt(proof={-1: None}), "non-negative"),
    ],
)
def test_receipts_that_must_be_refused(data: bytes, message: str) -> None:
    with pytest.raises(ReceiptError, match=message):
        verify_receipt(data, KEYS)


def test_the_root_is_what_a_proof_binds_not_the_stated_tree_size() -> None:
    # Leaf 4 has the same audit path in an 11-leaf and a 12-leaf tree shape, so a
    # receipt restating the size still walks to the same root. The size is the
    # receipt's statement; the root is the commitment that was checked.
    restated = verify_receipt(receipt(proof={-1: 12}), KEYS)
    assert restated.tree_size == 12
    assert restated.root_hash == verify_receipt(receipt(), KEYS).root_hash


def test_receipt_without_an_inclusion_proof_is_refused() -> None:
    body = envelope()
    protected = cbor2.dumps({1: -7, 4: KID, 395: 1})
    data = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, body, sign(KEY, protected, body)]))
    with pytest.raises(ReceiptError, match="no inclusion proof"):
        verify_receipt(data, KEYS)


def test_changing_the_payload_or_the_signed_header_is_detected() -> None:
    good = receipt()
    tag = cbor2.loads(good)
    protected, unprotected, payload, signature = tag.value
    swapped = cbor2.dumps(
        cbor2.CBORTag(
            18, [protected, unprotected, payload.replace(b"agent.example.com", b"evil.example.com"), signature]
        )
    )
    with pytest.raises(ReceiptError, match="not included"):
        verify_receipt(swapped, KEYS)
    # A header rewritten after signing: the proof still holds, the signature does not.
    reheader = cbor2.dumps({**cbor2.loads(protected), 15: {1: "other.example", 6: 1}})
    forged = cbor2.dumps(cbor2.CBORTag(18, [reheader, unprotected, payload, signature]))
    with pytest.raises(ReceiptError, match="does not verify"):
        verify_receipt(forged, KEYS)


def test_a_valid_proof_alone_is_not_enough() -> None:
    # A whole tree built around the attacker's payload, signed by a key that is not trusted.
    with pytest.raises(ReceiptError, match="not trusted"):
        verify_receipt(receipt(envelope(event(host="evil.example.com")), key=new_key()), KEYS)


# --- status token -------------------------------------------------------------


def test_status_token_verifies_and_returns_what_it_states() -> None:
    token = verify_status_token(status_token(), KEYS, now=NOW)
    assert (token.agent_id, token.status, token.kid) == (AGENT_ID, "ACTIVE", KID.hex())
    assert (token.issued_at, token.expires_at) == (NOW - 10, NOW + 3600)
    assert token.name == f"ans://v1.0.0.{FQDN}"


@pytest.mark.parametrize(
    ("kw", "now", "leeway", "message"),
    [
        ({"expires_at": NOW - 61}, NOW, 60, "expired"),
        ({"issued_at": NOW + 61}, NOW, 60, "future"),
        ({"expires_at": NOW - 1}, NOW, 0, "expired"),
        ({"key": new_key()}, NOW, 60, "not trusted"),
        ({"claims": {1: None}}, NOW, 60, "no agent"),
        ({"claims": {2: 7}}, NOW, 60, "no status"),
        ({"claims": {4: None}}, NOW, 60, "expiry"),
        ({"claims": {3: "soon"}}, NOW, 60, "issue time"),
    ],
)
def test_status_tokens_that_must_be_refused(kw: dict[str, Any], now: int, leeway: int, message: str) -> None:
    with pytest.raises(ReceiptError, match=message):
        verify_status_token(status_token(**kw), KEYS, now=now, leeway=leeway)


def test_leeway_tolerates_small_clock_differences() -> None:
    assert verify_status_token(status_token(expires_at=NOW - 30), KEYS, now=NOW, leeway=60).status == "ACTIVE"
    assert verify_status_token(status_token(issued_at=NOW + 30), KEYS, now=NOW, leeway=60).status == "ACTIVE"


def test_status_token_with_a_tampered_payload_is_refused() -> None:
    protected, unprotected, payload, signature = cbor2.loads(status_token(status="REVOKED")).value
    relabelled = cbor2.dumps({**cbor2.loads(payload), 2: "ACTIVE"})
    forged = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, relabelled, signature]))
    with pytest.raises(ReceiptError, match="does not verify"):
        verify_status_token(forged, KEYS, now=NOW)


def test_status_token_payload_that_is_not_a_map_is_refused() -> None:
    payload = cbor2.dumps([1, 2, 3])
    protected = cbor2.dumps({1: -7, 4: KID})
    data = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, sign(KEY, protected, payload)]))
    with pytest.raises(ReceiptError, match="not a map"):
        verify_status_token(data, KEYS, now=NOW)


# --- the resolver's verified mode ---------------------------------------------


def log(
    *,
    receipt_response: Any = None,
    token_response: Any = None,
    seen: list[str] | None = None,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if seen is not None:
            seen.append(path)
        if path == f"/v1/agents/{AGENT_ID}/receipt":
            served = receipt_response if receipt_response is not None else receipt()
        elif path == f"/v1/agents/{AGENT_ID}/status-token":
            served = token_response if token_response is not None else status_token()
        else:
            return httpx.Response(500)
        return served if isinstance(served, httpx.Response) else httpx.Response(200, content=served)

    return httpx.MockTransport(handler)


def verified(**kw: Any) -> AnsLogResolver:
    transport = log(
        receipt_response=kw.pop("receipt_response", None),
        token_response=kw.pop("token_response", None),
        seen=kw.pop("seen", None),
    )
    kw.setdefault("root_keys", key_line(KEY))
    kw.setdefault("agent_id_for", lambda agent_id: AGENT_ID)
    kw.setdefault("clock", lambda: NOW)
    return AnsLogResolver(LOG, transport=transport, **kw)


async def outcome_of(resolver: AnsLogResolver) -> tuple[Status, RecordView | None, str]:
    return await resolver.resolve_with_outcome(FQDN)


@pytest.mark.asyncio
async def test_verified_claim_is_read_from_signed_artifacts_only() -> None:
    seen: list[str] = []
    status, view, outcome = await outcome_of(verified(seen=seen))
    assert (status, outcome) == ("present", "present")
    assert view == RecordView(endpoint=CARD)
    # The unsigned badge route is never asked.
    assert seen == [f"/v1/agents/{AGENT_ID}/receipt", f"/v1/agents/{AGENT_ID}/status-token"]


@pytest.mark.asyncio
async def test_pinned_keys_may_be_a_parsed_mapping() -> None:
    assert (await outcome_of(verified(root_keys=KEYS)))[0] == "present"


def test_unusable_pinned_keys_fail_at_construction() -> None:
    with pytest.raises(ReceiptError):
        AnsLogResolver(LOG, agent_id_for=lambda a: AGENT_ID, root_keys="not a key line")


@pytest.mark.parametrize(
    "bad_receipt",
    [
        receipt(key=new_key()),  # signed by a key that is not pinned
        receipt(signature=b"\x01" * 64),
        receipt(proof={-4: b"\x00" * 32}),
        b"not a receipt",
        receipt(envelope(event(agent_id="00000000-0000-4000-8000-000000000000"))),  # another agent's event
    ],
)
@pytest.mark.asyncio
async def test_a_receipt_that_does_not_verify_for_this_entry_is_unverifiable(bad_receipt: bytes) -> None:
    assert await outcome_of(verified(receipt_response=bad_receipt)) == ("error", None, OUTCOME_UNVERIFIABLE)


@pytest.mark.parametrize(
    "bad_token",
    [
        status_token(key=new_key()),
        status_token(expires_at=NOW - 3600),
        status_token(issued_at=NOW + 3600),
        status_token(agent_id="00000000-0000-4000-8000-000000000000"),  # another agent's status
        b"not a token",
        httpx.Response(404),  # the sealed event is proven, its current status is not
    ],
)
@pytest.mark.asyncio
async def test_a_status_that_is_not_proven_current_is_unverifiable(bad_token: Any) -> None:
    assert await outcome_of(verified(token_response=bad_token)) == ("error", None, OUTCOME_UNVERIFIABLE)


@pytest.mark.parametrize(("status", "outcome"), [("REVOKED", OUTCOME_REVOKED), ("EXPIRED", OUTCOME_EXPIRED)])
@pytest.mark.asyncio
async def test_a_proven_status_that_is_not_live_is_not_a_claim_of_absence(status: str, outcome: str) -> None:
    assert await outcome_of(verified(token_response=status_token(status=status))) == ("error", None, outcome)


@pytest.mark.asyncio
async def test_no_receipt_for_the_entry_is_absent() -> None:
    assert await outcome_of(verified(receipt_response=httpx.Response(404))) == ("absent", None, "absent")


@pytest.mark.parametrize(
    ("response", "outcome"),
    [(httpx.Response(403), OUTCOME_REFUSED), (httpx.Response(503), OUTCOME_UNREACHABLE)],
)
@pytest.mark.asyncio
async def test_transport_outcomes_are_kept_on_either_route(response: httpx.Response, outcome: str) -> None:
    assert await outcome_of(verified(receipt_response=response)) == ("error", None, outcome)
    assert await outcome_of(verified(token_response=response)) == ("error", None, outcome)


@pytest.mark.asyncio
async def test_a_verified_payload_that_is_not_a_sealed_event_is_unparseable() -> None:
    assert await outcome_of(verified(receipt_response=receipt(b'{"not":"an envelope"}'))) == (
        "error",
        None,
        OUTCOME_UNPARSEABLE,
    )


@pytest.mark.asyncio
async def test_verified_entry_must_still_be_about_the_expected_host() -> None:
    other = receipt(envelope(event(host="other.example.com")))
    resolver = verified(receipt_response=other, owner_for=lambda agent_id: FQDN)
    assert await outcome_of(resolver) == ("error", None, OUTCOME_UNVERIFIABLE)


@pytest.mark.asyncio
async def test_clock_decides_whether_the_token_is_current() -> None:
    assert (await outcome_of(verified(clock=lambda: NOW + 3600 + 30)))[0] == "present"  # within leeway
    assert await outcome_of(verified(clock=lambda: NOW + 7200)) == ("error", None, OUTCOME_UNVERIFIABLE)
    assert await outcome_of(verified(clock=lambda: NOW + 3600 + 30, leeway=0)) == ("error", None, OUTCOME_UNVERIFIABLE)
