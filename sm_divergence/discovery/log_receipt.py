"""Verifying what a transparency log signs: a receipt and a status token.

A log that seals registrations can hand a reader two signed artifacts:

- a **receipt** — a COSE_Sign1 (RFC 9052) carrying the sealed event as its
  attached payload, with an inclusion proof for that event in the unprotected
  header. Verifying it shows that the log's key signed the event, that the event
  hashes to a leaf (RFC 9162 section 2.1.1) and that the leaf walks to the
  stated root (RFC 9162 section 2.1.3.2);
- a **status token** — a short-lived COSE_Sign1 whose payload states the
  agent's current status and when the statement expires.

Layout read here:

    receipt        18([ protected, { 396: { -1: tree_size, -2: leaf_index,
                                            -3: [path…], -4: root_hash } },
                        payload, signature ])
        protected  { 1: -7 (ES256), 4: kid, 395: 1, 15: { 1: issuer, 6: issued_at } }
    status token   18([ protected, {}, payload, signature ])
        payload    { 1: agent_id, 2: status, 3: issued_at, 4: expires_at, 5: name }

Signatures are ES256 in IEEE P1363 form over the ``Signature1`` structure. Keys
are ECDSA P-256, published one per line as
``<origin>+<keyhash>+<base64(0x02 || SPKI DER)>``; the 4-byte ``kid`` is the
first four bytes of ``SHA-256(SPKI DER)``.

**What this does not establish.** A receipt proves inclusion under the root it
states; it does not show that root to be the log's current one, nor that no
later event supersedes the one sealed. And every check is only as good as the
keys: keys fetched from the log being checked show the log is self-consistent,
not that it is the log you meant. Pin them out of band.

Needs the ``cose`` extra (``cbor2``, ``cryptography``), imported on first use.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

HASH_SIZE = 32
KID_SIZE = 4

_COSE_SIGN1_TAG = 18
_ALG_ES256 = -7
_VDS_RFC9162_SHA256 = 1
_LABEL_ALG, _LABEL_KID, _LABEL_CWT, _LABEL_VDS, _LABEL_VDP = 1, 4, 15, 395, 396
_CWT_ISS, _CWT_IAT = 1, 6
_PROOF_TREE_SIZE, _PROOF_LEAF_INDEX, _PROOF_PATH, _PROOF_ROOT = -1, -2, -3, -4
_TOKEN_AGENT, _TOKEN_STATUS, _TOKEN_IAT, _TOKEN_EXP, _TOKEN_NAME = 1, 2, 3, 4, 5
_NOTE_KEY_TYPE_ECDSA = 0x02
_P1363_SIZE = 64


class ReceiptError(ValueError):
    """A signed artifact that could not be verified. The message says which check failed."""


@dataclass(frozen=True)
class VerifiedReceipt:
    """A receipt whose signature and inclusion proof both verified.

    ``root_hash`` is the commitment that was checked. ``tree_size`` and
    ``leaf_index`` are the receipt's own statements: an audit path constrains
    them only as far as the tree's shape does.
    """

    payload: bytes
    tree_size: int
    leaf_index: int
    root_hash: bytes
    kid: str
    issuer: str | None = None
    issued_at: int | None = None


@dataclass(frozen=True)
class VerifiedStatusToken:
    """A status token whose signature verified and which has not expired."""

    agent_id: str
    status: str
    issued_at: int
    expires_at: int
    kid: str
    name: str | None = None


def _crypto() -> Any:
    try:
        import cbor2
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError("log verification needs cbor2 and cryptography: install 'sm-divergence[cose]'") from exc

    @dataclass(frozen=True)
    class _Libs:
        cbor2: Any
        InvalidSignature: Any
        hashes: Any
        serialization: Any
        ec: Any
        utils: Any

    return _Libs(cbor2, InvalidSignature, hashes, serialization, ec, utils)


# --- keys ---------------------------------------------------------------------


def key_id(public_key: Any) -> str:
    """The key's ``kid`` as hex: the first four bytes of ``SHA-256(SPKI DER)``."""
    libs = _crypto()
    spki = public_key.public_bytes(
        libs.serialization.Encoding.DER, libs.serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).digest()[:KID_SIZE].hex()


def _require_p256(public_key: Any) -> Any:
    libs = _crypto()
    if not isinstance(public_key, libs.ec.EllipticCurvePublicKey) or not isinstance(
        public_key.curve, libs.ec.SECP256R1
    ):
        raise ReceiptError("verification key is not ECDSA P-256")
    return public_key


def parse_root_keys(text: str | Iterable[str]) -> dict[str, Any]:
    """Read verification keys into ``{kid hex: public key}``.

    Accepts the published line format ``<origin>+<keyhash>+<base64(0x02 || SPKI
    DER)>`` (one key per line; a string of several lines, or an iterable of
    lines) and PEM public keys. A line whose stated key hash is not the hash of
    the key it carries is rejected, as is anything that is not an ECDSA P-256
    key. Raises ``ReceiptError`` if no key is read.
    """
    libs = _crypto()
    if isinstance(text, str):
        chunks = [text] if "-----BEGIN" in text else text.splitlines()
    else:
        chunks = list(text)

    keys: dict[str, Any] = {}
    for chunk in chunks:
        entry = chunk.strip()
        if not entry:
            continue
        if "-----BEGIN" in entry:
            for block in entry.split("-----END PUBLIC KEY-----"):
                if "-----BEGIN PUBLIC KEY-----" not in block:
                    continue
                pem = block[block.index("-----BEGIN PUBLIC KEY-----") :] + "-----END PUBLIC KEY-----\n"
                try:
                    key = libs.serialization.load_pem_public_key(pem.encode())
                except Exception as exc:
                    raise ReceiptError("verification key is not a readable PEM public key") from exc
                keys[key_id(_require_p256(key))] = key
            continue
        parts = entry.split("+", 2)
        if len(parts) != 3:
            raise ReceiptError("verification key line is not <origin>+<keyhash>+<key>")
        try:
            raw = base64.b64decode(parts[2], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ReceiptError("verification key is not base64") from exc
        if len(raw) < 2 or raw[0] != _NOTE_KEY_TYPE_ECDSA:
            raise ReceiptError("verification key is not of the ECDSA key type")
        try:
            key = libs.serialization.load_der_public_key(raw[1:])
        except Exception as exc:
            raise ReceiptError("verification key is not a readable SPKI") from exc
        kid = key_id(_require_p256(key))
        if parts[1].strip().lower() != kid:
            raise ReceiptError("verification key line states a key hash that is not its key's")
        keys[kid] = key
    if not keys:
        raise ReceiptError("no verification key was given")
    return keys


# --- RFC 9162 Merkle tree -----------------------------------------------------


def leaf_hash(entry: bytes) -> bytes:
    """RFC 9162 section 2.1.1: ``SHA-256(0x00 || entry)``."""
    return hashlib.sha256(b"\x00" + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 9162 section 2.1.1: ``SHA-256(0x01 || left || right)``."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_from_inclusion_proof(leaf: bytes, leaf_index: int, tree_size: int, path: Sequence[bytes]) -> bytes:
    """Walk an inclusion proof to the root it implies (RFC 9162 section 2.1.3.2).

    Raises ``ReceiptError`` for an index outside the tree, a node of the wrong
    size, or a path that is too short or too long for the stated position.
    """
    if tree_size <= 0:
        raise ReceiptError("inclusion proof states an empty tree")
    if not 0 <= leaf_index < tree_size:
        raise ReceiptError("inclusion proof states a leaf index outside the tree")
    if len(leaf) != HASH_SIZE:
        raise ReceiptError("leaf hash has the wrong size")
    fn, sn, node = leaf_index, tree_size - 1, leaf
    for sibling in path:
        if len(sibling) != HASH_SIZE:
            raise ReceiptError("inclusion proof holds a node of the wrong size")
        if sn == 0:
            raise ReceiptError("inclusion proof path is too long")
        if fn & 1 or fn == sn:
            node = node_hash(sibling, node)
            while fn and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ReceiptError("inclusion proof path is too short")
    return node


# --- COSE_Sign1 ---------------------------------------------------------------


@dataclass(frozen=True)
class _Sign1:
    protected_bytes: bytes
    protected: Mapping[Any, Any]
    unprotected: Mapping[Any, Any]
    payload: bytes
    signature: bytes


def _parse_sign1(data: bytes) -> _Sign1:
    libs = _crypto()
    try:
        obj = libs.cbor2.loads(data)
    except Exception as exc:
        raise ReceiptError("not CBOR") from exc
    if isinstance(obj, libs.cbor2.CBORTag):
        if obj.tag != _COSE_SIGN1_TAG:
            raise ReceiptError("not a COSE_Sign1 (wrong tag)")
        obj = obj.value
    if not isinstance(obj, (list, tuple)) or len(obj) != 4:
        raise ReceiptError("not a COSE_Sign1 (not a four-element array)")
    protected_bytes, unprotected, payload, signature = obj
    if not isinstance(protected_bytes, bytes) or not isinstance(signature, bytes):
        raise ReceiptError("COSE_Sign1 header or signature is not a byte string")
    if not isinstance(payload, bytes) or not payload:
        raise ReceiptError("COSE_Sign1 carries no attached payload")
    if not isinstance(unprotected, Mapping):
        raise ReceiptError("COSE_Sign1 unprotected header is not a map")
    try:
        protected = libs.cbor2.loads(protected_bytes)
    except Exception as exc:
        raise ReceiptError("COSE_Sign1 protected header is not CBOR") from exc
    if not isinstance(protected, Mapping):
        raise ReceiptError("COSE_Sign1 protected header is not a map")
    if protected.get(_LABEL_ALG) != _ALG_ES256:
        raise ReceiptError("COSE_Sign1 algorithm is not ES256")
    return _Sign1(protected_bytes, protected, unprotected, payload, signature)


def _verify_signature(sign1: _Sign1, keys: Mapping[str, Any]) -> str:
    """Verify the signature with the key the ``kid`` names; return that kid."""
    libs = _crypto()
    kid = sign1.protected.get(_LABEL_KID)
    if not isinstance(kid, bytes) or len(kid) != KID_SIZE:
        raise ReceiptError("COSE_Sign1 carries no usable kid")
    key = keys.get(kid.hex())
    if key is None:
        raise ReceiptError("COSE_Sign1 is signed by a key that is not trusted")
    if len(sign1.signature) != _P1363_SIZE:
        raise ReceiptError("ES256 signature has the wrong size")
    r = int.from_bytes(sign1.signature[:32], "big")
    s = int.from_bytes(sign1.signature[32:], "big")
    to_sign = libs.cbor2.dumps(["Signature1", sign1.protected_bytes, b"", sign1.payload])
    try:
        _require_p256(key).verify(libs.utils.encode_dss_signature(r, s), to_sign, libs.ec.ECDSA(libs.hashes.SHA256()))
    except libs.InvalidSignature as exc:
        raise ReceiptError("signature does not verify") from exc
    return kid.hex()


def _as_keys(keys: Mapping[str, Any] | str | Iterable[str]) -> Mapping[str, Any]:
    return keys if isinstance(keys, Mapping) else parse_root_keys(keys)


def _uint(value: Any, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReceiptError(f"{what} is not a non-negative integer")
    return value


def verify_receipt(data: bytes, keys: Mapping[str, Any] | str | Iterable[str]) -> VerifiedReceipt:
    """Verify a receipt; return its attached payload and proof position.

    Checks, in order: the structure and algorithm; that the attached payload
    hashes to a leaf which the inclusion proof walks to the stated root; and the
    signature, with the trusted key the ``kid`` names. ``keys`` is the mapping
    ``parse_root_keys`` returns, or anything it accepts. Raises ``ReceiptError``.
    """
    trusted = _as_keys(keys)
    sign1 = _parse_sign1(data)
    if sign1.protected.get(_LABEL_VDS) != _VDS_RFC9162_SHA256:
        raise ReceiptError("receipt does not use the RFC 9162 SHA-256 tree")
    proof = sign1.unprotected.get(_LABEL_VDP)
    if not isinstance(proof, Mapping):
        raise ReceiptError("receipt carries no inclusion proof")
    tree_size = _uint(proof.get(_PROOF_TREE_SIZE), "tree size")
    leaf_index = _uint(proof.get(_PROOF_LEAF_INDEX), "leaf index")
    path, root = proof.get(_PROOF_PATH), proof.get(_PROOF_ROOT)
    if not isinstance(path, (list, tuple)) or not all(isinstance(node, bytes) for node in path):
        raise ReceiptError("inclusion proof path is not a list of byte strings")
    if not isinstance(root, bytes) or len(root) != HASH_SIZE:
        raise ReceiptError("inclusion proof root has the wrong size")
    if root_from_inclusion_proof(leaf_hash(sign1.payload), leaf_index, tree_size, path) != root:
        raise ReceiptError("the payload is not included under the stated root")
    kid = _verify_signature(sign1, trusted)

    claims = sign1.protected.get(_LABEL_CWT)
    issuer = issued_at = None
    if isinstance(claims, Mapping):
        issuer = claims.get(_CWT_ISS) if isinstance(claims.get(_CWT_ISS), str) else None
        issued_at = claims.get(_CWT_IAT) if isinstance(claims.get(_CWT_IAT), int) else None
    return VerifiedReceipt(
        payload=sign1.payload,
        tree_size=tree_size,
        leaf_index=leaf_index,
        root_hash=root,
        kid=kid,
        issuer=issuer,
        issued_at=issued_at,
    )


def verify_status_token(
    data: bytes,
    keys: Mapping[str, Any] | str | Iterable[str],
    *,
    now: float | None = None,
    leeway: float = 60.0,
) -> VerifiedStatusToken:
    """Verify a status token; return what it states.

    Checks the structure, algorithm and signature, then that the token is
    current: not issued in the future and not expired, each within ``leeway``
    seconds. ``now`` defaults to the system clock. Raises ``ReceiptError``.
    """
    libs = _crypto()
    trusted = _as_keys(keys)
    sign1 = _parse_sign1(data)
    kid = _verify_signature(sign1, trusted)
    try:
        claims = libs.cbor2.loads(sign1.payload)
    except Exception as exc:
        raise ReceiptError("status token payload is not CBOR") from exc
    if not isinstance(claims, Mapping):
        raise ReceiptError("status token payload is not a map")
    agent_id, status = claims.get(_TOKEN_AGENT), claims.get(_TOKEN_STATUS)
    if not isinstance(agent_id, str) or not isinstance(status, str):
        raise ReceiptError("status token names no agent or no status")
    issued_at = _uint(claims.get(_TOKEN_IAT), "status token issue time")
    expires_at = _uint(claims.get(_TOKEN_EXP), "status token expiry")
    current = time.time() if now is None else now
    if issued_at > current + leeway:
        raise ReceiptError("status token is issued in the future")
    if expires_at < current - leeway:
        raise ReceiptError("status token has expired")
    name = claims.get(_TOKEN_NAME)
    return VerifiedStatusToken(
        agent_id=agent_id,
        status=status,
        issued_at=issued_at,
        expires_at=expires_at,
        kid=kid,
        name=name if isinstance(name, str) else None,
    )
