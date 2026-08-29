"""A deterministic endpoint canonicalization profile.

RFC 3986 Section 6 is under-determined: it names syntax-based normalization but
leaves percent-encoding, dot-segments, empty-versus-root path, fragments and IDNA
to the reader. Two conforming implementations can disagree, and a disagreement
here is a false `endpoint` divergence between honest registries.

This pins one profile, `endpoint-normalization/0.1`, and these cases are its test
vectors.
"""

from __future__ import annotations

import pytest

from sm_divergence.discovery.views import ENDPOINT_NORMALIZATION, normalize_endpoint


def same(a: str, b: str) -> bool:
    return normalize_endpoint(a) == normalize_endpoint(b)


def test_the_profile_is_named_and_versioned() -> None:
    assert ENDPOINT_NORMALIZATION == "endpoint-normalization/0.1"


# ── case ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "a,b",
    [
        ("HTTPS://Example.COM/a", "https://example.com/a"),
        ("https://EXAMPLE.com/a", "https://example.com/a"),
    ],
)
def test_scheme_and_host_are_case_insensitive(a: str, b: str) -> None:
    assert same(a, b)


def test_the_path_is_case_sensitive() -> None:
    # Only the scheme and host are case-insensitive. A path may address distinct
    # resources by case, so folding it would merge two different endpoints.
    assert not same("https://example.com/A", "https://example.com/a")


# ── port and path ────────────────────────────────────────────


def test_the_default_port_is_dropped() -> None:
    assert same("https://example.com:443/a", "https://example.com/a")
    assert same("http://example.com:80/a", "http://example.com/a")


def test_a_non_default_port_is_kept() -> None:
    assert not same("https://example.com:8443/a", "https://example.com/a")


def test_an_empty_path_becomes_root() -> None:
    assert same("https://example.com", "https://example.com/")


def test_dot_segments_are_removed() -> None:
    assert same("https://example.com/a/./b", "https://example.com/a/b")
    assert same("https://example.com/a/b/../c", "https://example.com/a/c")


# ── percent-encoding ─────────────────────────────────────────


def test_percent_encoding_is_uppercased() -> None:
    assert same("https://example.com/a%2fb", "https://example.com/a%2Fb")


def test_unreserved_characters_are_decoded() -> None:
    # RFC 3986 2.3: percent-encoding an unreserved character is equivalent to
    # not encoding it, so the decoded form is canonical.
    assert same("https://example.com/%7Euser", "https://example.com/~user")


def test_reserved_characters_stay_encoded() -> None:
    # %2F is an encoded slash and is NOT the same as a path separator. Decoding
    # it would merge two different endpoints.
    assert not same("https://example.com/a%2Fb", "https://example.com/a/b")


# ── query and fragment ───────────────────────────────────────


def test_the_query_is_byte_sensitive() -> None:
    # Query semantics belong to the server. Reordering or dropping parameters
    # would assert an equivalence this profile cannot know holds.
    assert not same("https://example.com/a?x=1&y=2", "https://example.com/a?y=2&x=1")
    assert not same("https://example.com/a?x=1", "https://example.com/a")


def test_the_fragment_is_removed() -> None:
    # A fragment is not sent to the server, so it cannot distinguish two
    # endpoints as addresses.
    assert same("https://example.com/a#top", "https://example.com/a")


# ── hostnames ────────────────────────────────────────────────


def test_an_internationalised_host_is_compared_as_punycode() -> None:
    assert same("https://Bücher.example/a", "https://xn--bcher-kva.example/a")


def test_a_trailing_dot_on_the_host_is_removed() -> None:
    assert same("https://example.com./a", "https://example.com/a")


# ── non-URIs ─────────────────────────────────────────────────


def test_a_value_that_is_not_a_uri_is_returned_unchanged() -> None:
    # Still compared, just not normalized. Guessing at a shape we do not
    # recognise would be worse than comparing it literally.
    assert normalize_endpoint("not a uri") == "not a uri"
    assert normalize_endpoint(None) is None
