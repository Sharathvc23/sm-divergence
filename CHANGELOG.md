# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

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
