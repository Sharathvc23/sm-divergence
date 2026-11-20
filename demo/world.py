"""The four places a travel company's booking agent is listed, built fresh for every run.

John's personal agent, Pim, is about to book a trip with Travel26. Before it sends anything, it has
to find Travel26's booking agent: which agent card is the real one. That answer is published in
four places, and a world is those four places:

- a **zone**: an SVCB row at the agent's name, served over DNS-over-HTTPS (RFC 8484) by two
  recursive resolvers, so the zone can be observed from two vantages;
- a **registry**: one JSON record per agent id;
- a **log**: a transparency log that seals each registration and hands out a signed receipt
  (COSE_Sign1, ES256, with an RFC 9162 inclusion proof) and a signed status token;
- a **catalog**: the JSON document the company publishes listing its agent cards.

Each source is a small HTTP application. The library's resolvers call it with their own HTTP
client; the site serves the same handlers under ``/runs/<id>/…`` so a visitor can open what the
library was told. A story changes what a *source* says. Nothing in the library is patched.

Everything here is fictional: ``.example`` names, keys made for the run.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import cbor2
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route

from sm_divergence.discovery import (
    AnsLogResolver,
    AnsV2Resolver,
    CatalogResolver,
    DnsZoneResolver,
    DohQuery,
    RecordView,
)

Log = Callable[[str, str], None]

FQDN = "booking.travel26.example"
CARD_URL = f"https://{FQDN}/.well-known/agent-card.json"
ELSEWHERE_URL = "https://booking.travel26-reservations.example/.well-known/agent-card.json"
AGENT_ID = "7c1e4a90-2b6d-4f3a-9d18-5e0a6c3b2f71"  # the id the registry and the log file it under
CATALOG_ID = "urn:air:travel26.example:booking"  # the id the catalog lists it under
CARD_TYPE = "application/a2a-agent-card+json"
LOG_ORIGIN = "log.registrar.example"
VANTAGES = ("resolver-a", "resolver-b")
DNS_MESSAGE = "application/dns-message"

CARD = {
    "name": "Travel26 Booking",
    "description": "Books flights and hotels for Travel26 customers.",
    "url": f"https://{FQDN}/a2a",
    "version": "1.4.0",
    "supportedInterfaces": [{"url": f"https://{FQDN}/a2a", "protocolBinding": "JSONRPC"}],
}
OTHER_CARD = {**CARD, "url": f"https://{FQDN}/a2a/v2", "version": "1.5.0"}


def card_bytes(card: dict[str, Any]) -> bytes:
    return json.dumps(card, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")


def svcb_row(url: str, digest_b64url: str) -> str:
    """The zone's row for the agent: descriptor address, its digest, the protocol it speaks."""
    return f'1 . alpn="a2a" port=443 key65400="{url}" key65401="{digest_b64url}" key65402="a2a"'


# --- the log's cryptography -----------------------------------------------------------------------


def _spki(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _kid(key: ec.EllipticCurvePrivateKey) -> bytes:
    return hashlib.sha256(_spki(key)).digest()[:4]


def key_line(key: ec.EllipticCurvePrivateKey) -> str:
    """The log's verification key as it publishes it: ``<origin>+<keyhash>+<base64(0x02 || SPKI)>``."""
    return f"{LOG_ORIGIN}+{_kid(key).hex()}+{base64.b64encode(bytes([2]) + _spki(key)).decode()}"


def _cose_sign(key: ec.EllipticCurvePrivateKey, protected: bytes, payload: bytes) -> bytes:
    to_sign = cbor2.dumps(["Signature1", protected, b"", payload])
    r, s = utils.decode_dss_signature(key.sign(to_sign, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[bytes]) -> bytes:
    """Merkle tree hash (RFC 9162 section 2.1.1)."""
    if len(leaves) == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = _split(len(leaves))
    return hashlib.sha256(b"\x01" + _mth(leaves[:k]) + _mth(leaves[k:])).digest()


def _audit_path(m: int, leaves: list[bytes]) -> list[bytes]:
    """Inclusion proof for leaf ``m`` (RFC 9162 section 2.1.3.1)."""
    if len(leaves) == 1:
        return []
    k = _split(len(leaves))
    if m < k:
        return [*_audit_path(m, leaves[:k]), _mth(leaves[k:])]
    return [*_audit_path(m - k, leaves[k:]), _mth(leaves[:k])]


@dataclass
class LogState:
    """What the log currently serves for the booking agent."""

    key: ec.EllipticCurvePrivateKey
    descriptor_url: str = CARD_URL
    digest_b64url: str = ""
    status: str = "ACTIVE"
    leaf_index: int = 4
    tree_size: int = 11

    def event(self) -> dict[str, Any]:
        return {
            "ansId": AGENT_ID,
            "ansName": f"ans://v1.4.0.{FQDN}",
            "eventType": "AGENT_REGISTERED",
            "raId": "registrar.example",
            "timestamp": "2026-10-02T09:14:00Z",
            "agent": {"host": FQDN, "name": "Travel26 Booking", "version": "1.4.0"},
            "attestations": {
                "dnsRecordsProvisioned": [
                    {"name": FQDN, "type": "SVCB", "data": svcb_row(self.descriptor_url, self.digest_b64url)}
                ],
                "domainValidation": "ACME-DNS-01",
            },
        }

    def envelope(self) -> bytes:
        doc = {
            "payload": {"logId": "log-1", "producer": {"event": self.event(), "keyId": "ra-1", "signature": "x..y"}},
            "schemaVersion": "V1",
            "signature": "x..y",
        }
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    def _leaves(self) -> list[bytes]:
        leaves = [f"registration-{i}.example".encode() for i in range(self.tree_size)]
        leaves[self.leaf_index] = self.envelope()
        return leaves

    def receipt(self, now: int) -> bytes:
        body, leaves = self.envelope(), self._leaves()
        protected = cbor2.dumps({1: -7, 4: _kid(self.key), 395: 1, 15: {1: LOG_ORIGIN, 6: now - 3600}})
        proof = {
            -1: self.tree_size,
            -2: self.leaf_index,
            -3: _audit_path(self.leaf_index, leaves),
            -4: _mth(leaves),
        }
        array = [protected, {396: proof}, body, _cose_sign(self.key, protected, body)]
        return cbor2.dumps(cbor2.CBORTag(18, array))

    def status_token(self, now: int) -> bytes:
        payload = cbor2.dumps({1: AGENT_ID, 2: self.status, 3: now - 30, 4: now + 3600, 5: f"ans://v1.4.0.{FQDN}"})
        protected = cbor2.dumps({3: "application/ans-status-token+cbor", 1: -7, 4: _kid(self.key)})
        return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, _cose_sign(self.key, protected, payload)]))

    def badge(self) -> dict[str, Any]:
        return {
            "schemaVersion": "V2",
            "status": self.status,
            "payload": {"logId": "log-1", "producer": {"keyId": "ra-1", "event": self.event()}},
        }


# --- the world ------------------------------------------------------------------------------------


@dataclass
class World:
    run_id: str
    base: str  # the public address of this run's sources, e.g. https://quilt.example/runs/ab12cd34
    log: Log
    zone: dict[str, dict[str, dict[str, list[str]]]] = field(default_factory=dict)  # vantage → name → type → rows
    registry: dict[str, Any] | None = None
    catalog: dict[str, Any] = field(default_factory=dict)
    catalog_status: int = 200
    requests: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.base = self.base.rstrip("/")
        self.prefix = urlsplit(self.base).path.rstrip("/")
        digest = sha256_b64url(card_bytes(CARD))
        self.card_digest_hex = sha256_hex(card_bytes(CARD))
        row = svcb_row(CARD_URL, digest)
        self.zone = {v: {FQDN: {"SVCB": [row]}} for v in VANTAGES}
        self.registry = {
            "agentId": AGENT_ID,
            "agentDisplayName": "Travel26 Booking",
            "endpoints": [
                {
                    "protocol": "A2A",
                    "agentUrl": f"https://{FQDN}/a2a",
                    "metaDataUrl": CARD_URL,
                    "metaDataHash": f"SHA256:{self.card_digest_hex}",
                }
            ],
        }
        self.catalog = {
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": CATALOG_ID,
                    "displayName": "Travel26 Booking",
                    "type": CARD_TYPE,
                    "url": CARD_URL,
                    "digest": f"sha256:{self.card_digest_hex}",
                },
                {
                    "identifier": "urn:air:travel26.example:support",
                    "displayName": "Travel26 Support",
                    "type": CARD_TYPE,
                    "url": "https://support.travel26.example/.well-known/agent-card.json",
                },
            ],
        }
        self.log_key = ec.generate_private_key(ec.SECP256R1())
        self.pinned_keys = key_line(self.log_key)  # what John pinned when he first trusted this log
        self.log_state = LogState(key=self.log_key, digest_b64url=digest)
        self.app = Starlette(routes=[Mount(self.prefix, routes=self._routes())] if self.prefix else self._routes())
        self.transport = httpx.ASGITransport(app=self.app)

    # -- the four sources, as HTTP -----------------------------------------------------------------

    def _routes(self) -> list[Route]:
        return [
            Route("/", self._index),
            Route("/dns/{vantage}/dns-query", self._doh, methods=["POST"]),
            Route("/dns/{vantage}/zone", self._zone_text),
            Route("/registry/ans/agents/{agent_id}", self._registry),
            Route("/log/v1/agents/{agent_id}", self._badge),
            Route("/log/v1/agents/{agent_id}/receipt", self._receipt),
            Route("/log/v1/agents/{agent_id}/status-token", self._status_token),
            Route("/log/root-keys", self._root_keys),
            Route("/catalog/.well-known/ai-catalog.json", self._catalog),
        ]

    def _seen(self, request: Request) -> None:
        self.requests.append(f"{request.method} {request.url.path[len(self.prefix) :]}")

    async def _index(self, request: Request) -> Response:
        return JSONResponse(
            {
                "run": self.run_id,
                "subject": FQDN,
                "note": "Fictional sources for one run of the demo. Each is asked by the library over HTTP.",
                "sources": {
                    "zone": {v: f"{self.base}/dns/{v}/zone" for v in VANTAGES},
                    "registry": f"{self.base}/registry/ans/agents/{AGENT_ID}",
                    "log": f"{self.base}/log/v1/agents/{AGENT_ID}",
                    "log_keys": f"{self.base}/log/root-keys",
                    "catalog": f"{self.base}/catalog/.well-known/ai-catalog.json",
                },
            }
        )

    async def _doh(self, request: Request) -> Response:
        self._seen(request)
        names = self.zone.get(request.path_params["vantage"])
        if names is None:
            return Response(status_code=404)
        try:
            query = dns.message.from_wire(await request.body())
            question = query.question[0]
        except Exception:
            return Response(status_code=400)
        reply = dns.message.make_response(query)
        reply.flags |= dns.flags.RA
        name = question.name.to_text(omit_final_dot=True).lower()
        if name not in names:
            reply.set_rcode(dns.rcode.NXDOMAIN)
        else:
            rows = names[name].get(dns.rdatatype.to_text(question.rdtype), [])
            if rows:
                reply.answer.append(
                    dns.rrset.from_text_list(question.name, 300, dns.rdataclass.IN, question.rdtype, rows)
                )
        return Response(reply.to_wire(), media_type=DNS_MESSAGE)

    async def _zone_text(self, request: Request) -> Response:
        names = self.zone.get(request.path_params["vantage"])
        if names is None:
            return Response(status_code=404)
        lines = [
            f"{name}. 300 IN {rdtype} {row}"
            for name, types in names.items()
            for rdtype, rows in types.items()
            for row in rows
        ]
        return PlainTextResponse("\n".join(lines) + "\n")

    async def _registry(self, request: Request) -> Response:
        self._seen(request)
        if self.registry is None or request.path_params["agent_id"] != AGENT_ID:
            return JSONResponse({"error": "not_registered"}, status_code=404)
        return JSONResponse(self.registry)

    def _is_ours(self, request: Request) -> bool:
        self._seen(request)
        return bool(request.path_params["agent_id"] == AGENT_ID)

    async def _badge(self, request: Request) -> Response:
        if not self._is_ours(request):
            return Response(status_code=404)
        return JSONResponse(self.log_state.badge())

    async def _receipt(self, request: Request) -> Response:
        if not self._is_ours(request):
            return Response(status_code=404)
        return Response(self.log_state.receipt(int(time.time())), media_type="application/scitt-receipt+cose")

    async def _status_token(self, request: Request) -> Response:
        if not self._is_ours(request):
            return Response(status_code=404)
        return Response(self.log_state.status_token(int(time.time())), media_type="application/ans-status-token+cbor")

    async def _root_keys(self, request: Request) -> Response:
        self._seen(request)
        return PlainTextResponse(key_line(self.log_state.key) + "\n")

    async def _catalog(self, request: Request) -> Response:
        self._seen(request)
        if self.catalog_status != 200:
            return PlainTextResponse("upstream unavailable\n", status_code=self.catalog_status)
        return JSONResponse(self.catalog)

    # -- what goes wrong in a story: always a source, never the library ------------------------------

    def registry_points_elsewhere(self) -> None:
        assert self.registry is not None
        self.registry["endpoints"][0]["metaDataUrl"] = ELSEWHERE_URL
        self.log("registry", f"My record for the booking agent now names a card at {ELSEWHERE_URL}.")

    def catalog_lists_another_card(self) -> None:
        other = sha256_hex(card_bytes(OTHER_CARD))
        self.catalog["entries"][0]["digest"] = f"sha256:{other}"
        self.log("catalog", f"Same address for the card, but the digest I list is sha256:{other[:16]}…")

    def registry_forgets(self) -> None:
        self.registry = None
        self.log("registry", "I have no record of that agent id: 404, not registered.")

    def zone_answers_differently_from(self, vantage: str) -> None:
        self.zone[vantage][FQDN]["SVCB"] = [svcb_row(ELSEWHERE_URL, sha256_b64url(card_bytes(CARD)))]
        self.log(
            "zone",
            f"Asked through {vantage}, the zone names a card at {ELSEWHERE_URL}. Through the other, the usual one.",
        )

    def zone_is_tampered(self) -> None:
        row = svcb_row(ELSEWHERE_URL, sha256_b64url(card_bytes(CARD)))
        for vantage in VANTAGES:
            self.zone[vantage][FQDN]["SVCB"] = [row]
        self.log(
            "zone", f"Whoever controls my answers today has me naming a card at {ELSEWHERE_URL}, from every resolver."
        )

    def catalog_goes_down(self) -> None:
        self.catalog_status = 503
        self.log("catalog", "503: the catalog host is not answering right now.")

    def log_revokes(self) -> None:
        self.log_state.status = "REVOKED"
        self.log("log", "The registration is sealed and unchanged, but its current status is REVOKED.")

    def log_is_impersonated(self) -> None:
        """Someone else answers at the log's address, with their own key, for a card of their choosing."""
        self.log_state = LogState(
            key=ec.generate_private_key(ec.SECP256R1()),
            descriptor_url=ELSEWHERE_URL,
            digest_b64url=sha256_b64url(card_bytes(CARD)),
        )
        self.log(
            "log", "(impersonated) Here is a receipt, a status token and my key. They all check out against each other."
        )

    # -- the sweeper's side ----------------------------------------------------------------------------

    async def fetch_log_keys(self) -> str:
        """Ask the log for its own verification key: all a client can do if it never pinned one."""
        async with httpx.AsyncClient(transport=self.transport) as client:
            return (await client.get(f"{self.base}/log/root-keys")).text.strip()

    def sources(self, *, log_keys: str | None = None) -> list[Any]:
        """One resolver per place the agent is listed. ``log_keys`` turns on receipt verification."""
        zone = [
            DnsZoneResolver(
                query=DohQuery(f"{self.base}/dns/{v}/dns-query", transport=self.transport),
                protocol="a2a",
                label="zone",
                vantage=v,
            )
            for v in VANTAGES
        ]
        registry = AnsV2Resolver(
            f"{self.base}/registry",
            ansname_for=lambda _fqdn: AGENT_ID,
            protocol="a2a",
            not_found_is_absent=True,  # this registry documents 404 as "not registered"
            transport=self.transport,
            label="registry",
        )
        log = AnsLogResolver(
            f"{self.base}/log",
            agent_id_for=lambda _fqdn: AGENT_ID,
            owner_for=lambda fqdn: fqdn,
            protocol="a2a",
            root_keys=log_keys,
            transport=self.transport,
            label="log",
        )
        catalog = CatalogResolver(
            f"{self.base}/catalog",
            identifier_for=lambda _fqdn: CATALOG_ID,
            artifact_type=CARD_TYPE,
            transport=self.transport,
            label="catalog",
        )
        return [*zone, registry, log, catalog]


def expected_view() -> RecordView:
    """What every honest source says, once reduced to one view."""
    return RecordView(endpoint=CARD_URL, digest=f"sha256:{sha256_hex(card_bytes(CARD))}")
