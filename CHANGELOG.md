# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `demo/`: a live demo site (Starlette) with eight stories run against four
  fictional sources built per run — a zone over DNS-over-HTTPS, a registry, a
  log issuing signed receipts, a catalog — plus an in-browser verifier for the
  Corroboration Record, a `Dockerfile` and `railway.json`. New `site` extra.
  The installed package is unchanged.

## [0.13.0] — 2026-11-19

More sources, read alike: a DNS zone, a registration log (optionally verified
against its signing keys) and a published catalog join the registries, each
with the same rule that anything short of a readable answer is `error`, never
`absent`. No kernel change; `sm-resolver` 0.7 is unchanged.

**Breaking:** two `AnsV2Resolver` defaults change — see *Changed*.

### Added

- **`DnsSvcbResolver`** (`discovery/dns_records.py`) — the SVCB rows (RFC 9460)
  at the agent's FQDN, one row per agent protocol. Maps the row's descriptor (or
  its service endpoint, with `target="service"`) onto `endpoint` and the
  descriptor digest onto `digest`. Follows AliasMode within a bound, ignores
  rows whose `mandatory` lists a key it does not implement, selects by agent
  protocol and priority. `SvcParamKeyMap` names the agent-specific SvcParamKeys,
  which have no assigned code point; the default is the Private Use block
  65400–65409.
- **`DnsTxtResolver`** — the `v=ans1` TXT rows at `_ans.{fqdn}`; `url` →
  `endpoint`.
- **Never a false `absent` from DNS.** NXDOMAIN, an empty answer and an alias to
  `.` are absence. A timeout, a failing resolver, an unreadable row, rows that
  disagree at equal priority, an id with no DNS name, and — with
  `require_dnssec` — an unauthenticated answer *or denial* are `error` claims
  with an outcome saying why.
- **`ai.stellarminds.dns.ambiguous-rrset`** — the first namespaced outcome:
  equal-priority rows that reduce to different views.
- **`DnspythonQuery`** — the default DNS network path, behind an injectable
  `DnsQuery` seam. Tested over the wire against a loopback server.
- **`dns` extra** (`dnspython>=2.6`), imported only when a default DNS query is
  built. A base install and every other resolver stay `httpx`-only.
- **`normalize_digest`** and the `digest-normalization/0.1` profile.
- **`AnsLogResolver`** (`discovery/ans_log.py`) — a transparency log's public
  badge route (`GET {log}/v1/agents/{agentId}`, no credential) as a source. The
  DNS records the badge attests are reduced by the same rules as the DNS
  resolvers, so a log and the zone it sealed compare directly. The entry is
  named by the caller or located through the `v=ans-badge1` TXT row; a row
  naming another log is `unverifiable`. `REVOKED` / `EXPIRED` registrations, an
  entry about another host, and a name with no badge row
  (`ai.stellarminds.ans.no-badge`) are `error` claims, never `absent`. Signatures
  and receipts are not verified.
- **`CatalogResolver`** (`discovery/catalog.py`) — a publisher's AI Catalog
  document as a source. The entry whose `identifier` names the subject gives
  `url` → `endpoint` and `digest` → `digest`. Searches inline nested catalogs;
  reads nested catalogs by `url` only with `follow_nested`, within depth and
  document bounds. Takes the latest of several versions; `artifact_type` selects
  one media type. No catalog (`ai.stellarminds.catalog.no-catalog`), a listing
  not read in full (`…nested-not-read`) and candidates that disagree
  (`…ambiguous-entry`) are `error` claims, never `absent`.
- **Verified mode for `AnsLogResolver`** (`root_keys=`). The event is read from
  the log's receipt and the status from its status token, both COSE_Sign1 under
  the caller's pinned keys; the unsigned badge route is not requested. A receipt
  for another agent's event, a token for another agent, an expired token, an
  untrusted key and a missing status token are all `error`/`unverifiable`.
- **`discovery/log_receipt.py`** — `verify_receipt` (ES256 signature and RFC 9162
  inclusion proof), `verify_status_token`, `parse_root_keys`. Checked against an
  independent recursive construction of the Merkle tree for every leaf of every
  tree size up to 69.
- **`cose` extra** (`cbor2`, `cryptography`) and **`ans` extra** (`cose` plus
  `dns`), both imported on first use only.
- **`DnsZoneResolver`** — one zone as one source: SVCB rows first, the `v=ans1`
  TXT rows only when no SVCB row exists. It does not fall back from an `error`.
- **`DohQuery`** — DNS over HTTPS (RFC 8484, wire format) as a `DnsQuery`: for
  networks that filter UDP port 53, and as an independent second vantage.
- **`CatalogResolver(follow_redirects=…)`** and the outcome
  `ai.stellarminds.catalog.redirected`.
- **`examples/live_sweep.py`** — corroborate one subject across live sources
  from the command line (not part of the offline example set).
- **`SubjectMap`** (`discovery/subjects.py`) — the names one subject goes by in
  each source, handed to resolvers as their mapping callables. A subject with no
  name for a source is an `error` claim from it and no request is sent; tested
  for every resolver that takes a mapping, beside a source that does hold the
  subject, so a correspondence gap cannot become an omission finding.
- **`CatalogResolver(match_on=…)`** — compare an entry member other than
  `identifier`, for catalogs whose identifiers are content-addressed and change
  with every revision.
- **`CatalogResolver(inline_endpoint=…)`** and **`a2a_interface_url(binding)`** —
  read the service endpoint out of an agent card carried inline. Several
  interfaces with no binding chosen is `ai.stellarminds.catalog.ambiguous-entry`.
- **`reduce_svcb_rows` / `reduce_ans_txt`** — the pure row-to-claim reductions,
  shared by the DNS resolvers and the log resolver.
- **`ans_agent_adapter`** — a `RecordAdapter` for an agent record that lists
  `endpoints[]` (`agentUrl`, `metaDataUrl`, `metaDataHash`, `protocol`).
- **`fetch_view(not_found=…)`** — what a not-found answer means on a route.

### Fixed

- **`AnsLogResolver` reads the record shapes logs actually publish.** The
  attested records may be a map from owner name to value as well as a list of
  `{name, type, data}` objects, and the badge TXT row may be `v=ra-badge1` at
  `_ra-badge.{fqdn}` as well as `v=ans-badge1` at `_ans-badge.{fqdn}`. Without
  this, a log publishing the map shape was `unparseable` and a zone publishing
  the other badge label had no locatable entry.
- **`CatalogResolver`: a redirect is no longer reported as `unreachable`.**

### Changed

- **`AnsV2Resolver`: a not-found answer is no claim by default (breaking).** A
  `404`, or a `200` body that says "not found", is now `error` instead of
  `absent`: on a credentialed by-id route it may only mean the caller cannot see
  the record. Pass `not_found_is_absent=True` to restore the previous
  classification on a route where not-found can mean nothing else.
- **`AnsV2Resolver`: the default adapter reads `endpoints[]` (breaking).** The
  default is now `ans_agent_adapter(protocol=…, target=…)`, with `protocol` and
  `target` as constructor arguments. A record with a top-level `endpoint` and no
  `endpoints` list is read as before; pass `adapter=default_adapter` for the
  previous behavior in every case. With several protocols registered and no
  `protocol` chosen the result is `error`, not an arbitrary entry.
- `AnsV2Resolver.resolve` no longer raises when `ansname_for` does.
- **`RecordView.comparable()` canonicalizes `digest`.** One SHA-256 spelled as
  prefixed hex, bare hex, or base64 / base64url of the raw bytes now compares
  equal, and a `digest` finding reports the canonical `sha256:<hex>` form. A
  value the profile does not recognize is compared literally, as before. This
  removes a false `digest` divergence between two honest sources; it cannot
  hide a real one, since distinct digests stay distinct.

## [0.12.0] — 2026-10-30

Aligns the discovery layer with registry-assisted resolution of known subjects
(the DAWN-aligned `known-subject-resolution-02` profile). Tracks
`draft-chandra-agent-registry-corroboration-02` (in preparation). Requires
`sm-resolver` 0.7.

### Added

- **`KnownSubjectResolver`** (`discovery/known_subject.py`) — one hop,
  `POST /resolve`, terminal target. Maps a Resolution Target Object onto the
  view: `targetUrl` → `endpoint`, `targetDigest` → `digest`, `sequence` and
  `authority.issuer` → the lease position. Expired, revoked, sequence-less or
  registry-as-target responses are `error` claims with outcomes that say why
  (`expired`, `revoked`, `unverifiable`, `refused`); RFC 9457 problem codes map
  onto the same vocabulary. Optional registry-provenance check. Never evaluates
  Authority Evidence, never fans out, never follows a registry as a target.
- **`RecordView.digest`** — compared when both sides carry one. Two registries
  agreeing on an address but not on what it serves is host-level substitution,
  a kind the endpoint comparison could not express.
- **`RecordView.sequence` / `sequence_scope` / `authority_issuer`** and
  `RecordView.binding()` — the lease position, read by the kernel's
  supersession rule. Not compared.
- **`stale_binding`** surfaces in the discovery layer: a registry one sequence
  behind is attributed, not accused of tampering.
- CLI: `--resolution-registry URL` (repeatable) and `--identity-type TYPE`.
- `examples/known_subject_sweep.py` — stale vs. tampered vs. unrelated-scope,
  network-free.

### Changed

- **Kernel resolves from git for development and CI; release gated on PyPI.**
  `[tool.uv.sources]` pins `sm-resolver` to a commit, and CI runs
  `uv sync --locked`, so this repo cannot go red because the kernel's PyPI
  release has not landed yet (the failure mode of 0.12.0's first CI run, which
  uv reports with a misleading "Python version" hint). The published wheel
  still declares `sm-resolver>=0.7` to PyPI consumers, so the release workflow
  now refuses to publish until that floor is actually on PyPI
  (`scripts/check_kernel_published.py`), with the tag command to run first.
- **Record format `corroboration/0.4`.** A claim entry whose view exposes a
  lease position carries `binding: {sequence, scope}`, so a `stale_binding`
  finding is re-derivable from recorded bytes. `0.1`–`0.3` remain verifiable.
- `NandaIndexV2Resolver` is marked **legacy**: the two-hop "index points,
  registry proves" topology is what the known-subject profile forbids (no
  inter-registry forwarding; a target MUST NOT be a generic Resolution
  Registry). Kept for registries still exposing it; unchanged in behaviour.
- README and SPEC §7.1, §9 updated; spec version `divergence/0.4-draft`.

## [0.11.0] — 2026-08-28

Three review findings on `-01`. Tracks
`draft-chandra-agent-registry-corroboration-02` (in preparation).

### Added

- **`answer_scopes` on the Corroboration Record**, and `scope_evidence()` to
  build it. `declared: true` with a sequence number said a scope was *allegedly*
  matched; it did not say which `{field, vantage_class}` rule, or which bytes the
  sequence referred to. A third party holding the record could not reproduce the
  decision, which contradicts the property this format asserts throughout:
  verifiable from recorded bytes.

  Each entry carries `label`, `subject`, `seq`, `scope_digest` and `scopes`. The
  digest is what makes it evidence rather than a restatement — a verifier already
  holding a bundle can tell whether it is the one that was used. The contents are
  carried too, because a verifier that does *not* hold it would otherwise have to
  fetch it, and a fetch is what offline verification exists to avoid.

  Present and empty when no scope was used: "no scope applied" and "this
  implementation does not record scopes" are different facts.

- **`verify_history_proof`** — the evidence envelope for prior publication.
  `scope_violation` may not be raised without evidence that a scope predates the
  observation it contradicts, and nothing here provides it. Leaving the
  *interface* undefined too would mean a deployment that does have a witnessed
  history has no interoperable way to record its proof.

  The envelope is defined; the mechanism is not. What is checkable without
  knowing the mechanism is the shape and the binding to specific scope bytes.
  **Accepting the envelope is not accepting the proof**, and that boundary is
  pinned by a test rather than left to a docstring.

### Changed

- **`endpoint-normalization/0.1`.** RFC 3986 Section 6 leaves percent-encoding,
  dot-segments, empty-versus-root path, fragments and IDNA to the reader, so two
  conforming implementations could disagree — and a disagreement here is a false
  `endpoint` divergence between honest registries.

  Now pinned: unreserved percent-escapes decoded and the rest uppercased,
  dot-segments removed, fragment dropped, query byte-sensitive, hosts compared as
  punycode with any trailing dot removed. The path stays case-sensitive; only the
  scheme and host fold. `tests/test_endpoint_canonicalization.py` is the vector
  set.

- Requires `sm-resolver` >= 0.6 (finding identity excludes observed values).

## [0.10.0] — 2026-08-28

The record names its signature algorithm, and the name is bound to the key.
Tracks `draft-chandra-agent-registry-corroboration-02` (in preparation).

### Added

- **`alg` on the Corroboration Record**, carrying the JOSE/COSE identifier
  (`EdDSA`). The algorithm appeared nowhere in the record; a verifier had to know
  it out of band, and a second algorithm could not be introduced without silently
  changing what every existing record meant.

- **`alg_from_did_key`**, and the rule that makes the member safe. A `did:key`
  already encodes the key type in its multicodec prefix, so the algorithm was
  always discoverable. Naming it is the easy half.

  **The half that matters is the binding: `alg` MUST agree with the key type the
  `sweeper` did:key encodes.** A verifier that reads `alg` and trusts it has
  gained a downgrade vector, not agility — a record could claim one algorithm
  while the signature was made with another. The key is authoritative; `alg`
  states the obligation rather than deciding it.

  Adding a second algorithm is now an entry in one table.

### Changed

- **`CORROBORATION_VERSION` is `corroboration/0.3`.** `alg` is REQUIRED from this
  version. Records at `0.1` and `0.2` have no such member and Ed25519 is implied;
  if one names an algorithm, it must still agree.

  Requiring it unconditionally invalidated every record already issued — the same
  failure `ACCEPTED_RECORD_VERSIONS` exists to prevent, arriving through a
  different door. Caught by running the full suite, and now pinned by a test.

- Requires `sm-resolver` >= 0.5 (the seeded outcome vocabulary; 0.4.0 is skipped — its protocol change type-broke consumers and was corrected in 0.5.0).

## [0.9.0] — 2026-08-27

Registry-operator identity and the Answer Scope — a source declaring, in
advance, which fields it varies and along which vantage class. Tracks
`draft-chandra-agent-registry-corroboration-01`.

### Added
- `OperatorDescription` / `build_operator_description` /
  `verify_operator_description` (`operator-description/0.1`). A `Resolver` is
  identified only by `label`, a URL; the subject, the served record and the
  sweeper all have keys, but the source *as an operator* had none, so nothing a
  registry signed about itself could be checked. Verification is two-part: the
  signature proves only that *some* operator authored the bundle, so the bundle
  must also name the label it was **served from** — serving it there is what
  demonstrates control of it. Labels match by exact equality, no URL
  normalisation.
- `AnswerScope` / `build_answer_scope` / `verify_answer_scope`
  (`answer-scope/0.1`), in the new `sm_divergence.licensing` package. Declares an
  **axis** (`{"field": "endpoint", "vantage_class": "region"}`), never a mapping.
  Rejects a non-occupiable `vantage_class`, a wildcard at the token level even
  when the accepted class set is widened, a field declared twice, and more than
  `MAX_SCOPES` entries. An empty `scopes` list verifies and positively asserts
  *no* variation — distinct from publishing nothing, which is ambiguous between
  "does not vary" and "does not implement this".
- `ACCEPTED_RECORD_VERSIONS`. `verify_corroboration_record` now checks the
  record's `version` against it, gating on a **set** rather than equality so
  that records issued before this revision stay verifiable.

### Changed
- **`CORROBORATION_VERSION` is `corroboration/0.2`.** Findings carry `declared`
  and `declaration_version`. `corroboration/0.1` records remain acceptable; the
  absent members read as undeclared.
- Requires `sm-resolver` >= 0.3 (the declared-divergence `Finding` members and
  cohort comparison). **Release `sm-resolver` 0.3.0 first** — this floor cannot
  resolve until it is published.

## [0.8.0] — 2026-07-04

The signed Corroboration Record, the portable agent self-description, and a
vantage-aware diff, on [`sm-resolver`](https://pypi.org/project/sm-resolver/)
≥ 0.2 (the vantage-aware claim model, `SweepResult`, confirmation). With the
`sm-resolver` kernel, this package is the reference implementation of the IETF
draft *Multi-Source Corroboration for AI Agent Discovery*
(`draft-chandra-agent-registry-corroboration-00`).

### Added
- **Signed Corroboration Record** (`sm_divergence.record`, draft §9) —
  `build_corroboration_record` / `sign_sweep` seal a `SweepResult` into a
  content-addressed, signed record (`record_id` = CORR-DIGEST = SHA-256 of the
  JCS body; `sweeper` `did:key` + Ed25519 signature). One record per subject,
  **whatever the verdict** — the `AGREE` record is the positive attestation that
  the sweep ran. `verify_corroboration_record` recomputes the digest and checks
  the signature offline, with optional `trusted_sweeper` pinning.
- **RFC 3986 endpoint normalization** (draft §5) — `normalize_endpoint` (applied
  in `RecordView.comparable()`): lowercase scheme/host, drop default ports,
  empty path → `/`, so two spellings of one endpoint are not a false divergence.
- `_signing.corr_digest` and `_signing.rfc3339` helpers.
- `python -m sm_divergence check --sweeper-key PATH` emits signed records.

### Changed
- **BREAKING:** the self-description bundle is now a flat
  `{version: "self-description/0.1", subject, seq, aliases, endpoints,
  signature}` object. `did` → `subject`, the `services{}` map → an
  `endpoints[]` array, and `issued_at`/`expires_at` are **removed** (freshness is
  supersession by `seq`, so a verifier needs no clock). `build_self_description`
  takes `endpoints` (a list) and drops `now`/`ttl_s`; `verify_self_description`
  drops `now`. `SelfDescription.service()` is removed; `.endpoints` is added.
- **BREAKING:** `check_once` and `DivergenceDetector.check` return
  `list[SweepResult]` (verdict + claims + findings), not `list[Finding]` — the
  kernel change surfaced here. `DivergenceDetector` accepts `staleness_window_s`.
- The CLI reports a verdict per subject and exits `2` only on `DIVERGENT`.

## [0.7.1] — 2026-07-04

Initial public release — catch a cheating registry (or any source agents resolve
through) by corroboration, on the [`sm-resolver`](https://pypi.org/project/sm-resolver/)
kernel.

### Added
- **Discovery layer** (`sm_divergence.discovery`) — corroborate registries about an
  agent: `omission` (present on one, positively absent on another), `endpoint`
  (unsigned endpoint disagreement), and `did` (verified-attestation key
  disagreement). `HttpByIdResolver` for NEST-style `GET /api/agents/{id}`,
  `NandaIndexV2Resolver` for the NANDA Index two-hop resolve, mixed freely in one
  `DivergenceDetector`; `signed_record_adapter` (optional `attestation` extra)
  supplies verified DIDs. An unreachable source is excluded — a timeout is not a
  claim.
- **Identity layer** (`sm_divergence.identity`) — corroborate an agent's DID
  methods on the one field that must agree, its verification key: `DidKeyResolver`
  (offline root of truth), `DidWebResolver`, `UniversalResolverResolver`. A method
  serving a different key than the root `did:key` is a `key` divergence.
- **Signed portable self-description** — the agent signs its own aliases + service
  endpoints with its `did:key`, so cross-namespace correspondence is proven, not
  configured. Hardened against the artifact's own failure modes: a monotonic
  `seq` with supersession (replay resistance), distribution corroborated across
  sources (`corroborate_descriptions`), `agent_equivocation` detection (the same
  key signing two conflicting descriptions), and alias closure (a record reached
  via a claimed alias that doesn't bind back to the `did:key` contributes no
  claim, never a divergence).
- **Uniform findings** — every `Finding` is `omission` or a field name, with a
  uniform `{"field": …, "values": {source: value}}` detail, deduped by
  fingerprint; wire an `on_finding` callback for long-running use.
- **CLI** — `python -m sm_divergence check --registry … [--nanda-index …] --watch …`;
  exit `2` on any divergence (cron/CI-friendly), `--json`, `--attestation`.
- Built on the source-agnostic `sm-resolver` kernel (`Resolver[T]`, the `View`
  contract, `diff_views`, `Corroborator`), re-exported from the top level.
- Full documentation set (README, WHITEPAPER, SPEC, GOVERNANCE, CONTRIBUTING),
  runnable examples, and PyPI trusted-publishing release workflow.
