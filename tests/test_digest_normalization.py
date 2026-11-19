"""The vector set for ``digest-normalization/0.1``.

Sources spell one SHA-256 differently: a prefixed hex string, bare hex, or
base64url of the raw bytes. The profile pins one canonical form so two honest
sources serving the same document do not produce a false ``digest`` divergence,
and leaves anything it does not recognize untouched.
"""

from __future__ import annotations

import base64
import hashlib

import pytest

from sm_divergence.discovery import DIGEST, DIGEST_NORMALIZATION, RecordView, normalize_digest

DOC = b'{"name":"agent"}'
RAW = hashlib.sha256(DOC).digest()
HEX = RAW.hex()
CANONICAL = "sha256:" + HEX
B64URL = base64.urlsafe_b64encode(RAW).decode().rstrip("=")
B64STD = base64.b64encode(RAW).decode()


def test_profile_identifier_is_pinned() -> None:
    assert DIGEST_NORMALIZATION == "digest-normalization/0.1"


def test_fixture_matches_the_published_vector() -> None:
    # The values the contract's vectors quote; a change here is a change to them.
    assert B64URL == "9s_HMOu6_nLBerzY8AS1gJcOWqy_67fWyIMoKtfwqPU"
    assert HEX == "f6cfc730ebbafe72c17abcd8f004b580970e5aacbfebb7d6c883282ad7f0a8f5"


@pytest.mark.parametrize(
    "spelling",
    [
        HEX,
        HEX.upper(),
        "sha256:" + HEX,
        "SHA256:" + HEX.upper(),
        "sha-256:" + HEX,
        B64URL,
        B64URL + "=",
        B64STD,
        B64STD.rstrip("="),
        "sha256:" + B64URL,
        "sha-256:" + B64STD,
    ],
)
def test_every_spelling_of_one_sha256_is_canonical(spelling: str) -> None:
    assert normalize_digest(spelling) == CANONICAL


@pytest.mark.parametrize(
    "value",
    [
        "sha256:AAAA",  # too short to be a SHA-256
        "not-a-digest",
        "sha512:" + "a" * 128,  # another algorithm
        "a" * 63,  # one character short of hex
        B64URL[:-1],  # one character short of base64
        B64URL + "==",  # over-padded
        "!" * 43,  # right length, not base64
        "",
    ],
)
def test_unrecognized_values_are_compared_literally(value: str) -> None:
    assert normalize_digest(value) == value


def test_none_stays_none() -> None:
    assert normalize_digest(None) is None


def test_base64_of_the_wrong_length_is_not_a_sha256() -> None:
    short = base64.urlsafe_b64encode(b"\x00" * 31).decode()
    assert normalize_digest(short) == short


def test_view_compares_the_canonical_form_but_keeps_what_was_served() -> None:
    served = RecordView(endpoint="https://a.example/card.json", digest=B64URL)
    assert served.digest == B64URL
    assert served.comparable()[DIGEST] == CANONICAL


def test_two_spellings_of_one_digest_compare_equal_in_the_view() -> None:
    a = RecordView(endpoint="https://a.example/card.json", digest=B64URL)
    b = RecordView(endpoint="https://a.example/card.json", digest="sha256:" + HEX.upper())
    assert a.comparable() == b.comparable()


def test_two_different_digests_still_differ() -> None:
    other = "sha256:" + hashlib.sha256(b"other").hexdigest()
    a = RecordView(digest=B64URL)
    b = RecordView(digest=other)
    assert a.comparable()[DIGEST] != b.comparable()[DIGEST]
