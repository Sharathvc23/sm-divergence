# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.7.0] — 2026-07-04

Self-description hardening — replay resistance, dogfooded distribution, and alias
closure. Also the system's first **agent-equivocation** detection.

### Added
- **`seq` + supersession** — the self-description carries a monotonic `seq`
  (signed); highest supersedes. `build_self_description(..., seq=N)` is now
  required. Closes the replay hole where an unexpired but superseded description
  could be served as "the agent's own signature."
- **`reconcile_descriptions` / `DescriptionReconciliation`** — reconcile
  descriptions gathered from multiple sources (`seq`-aware): the surviving
  highest-`seq` `canonical`, plus findings `agent_equivocation` (two valid
  descriptions at the same `seq` with different content → the agent's key signed
  a conflict; correspondence fails closed), `omission`, and `stale_description`.
- **`HttpDescriptionResolver` + `corroborate_descriptions`** — fetch + verify the
  description from every source and reconcile, so the description's own
  distribution (omission / replay) is corroborated, not trusted from one source.
- **`AliasClosureResolver` + `binds_by_did` (discovery) / `binds_by_key`
  (identity)** — a record reached via a self-asserted alias that does not bind
  back to the agent's `did:key` contributes no claim, never a divergence. Prevents
  a malicious agent from manufacturing a divergence by naming a victim's alias.

### Changed
- `build_self_description` gains a required `seq`; `SelfDescription` gains `seq`
  and `content_key()`. `verify_self_description` parses and requires `seq`.

## [0.6.0] — 2026-07-04

The kernel is extracted. The source-agnostic core (`Resolver[T]`, `View`,
`diff_views`, `Corroborator`, `Finding`) now lives in its own package,
[`sm-resolver`](https://github.com/Sharathvc23/sm-resolver), and `sm-divergence`
depends on it — the extraction the layered design was built toward, triggered
once the identity layer joined discovery as a second consumer.

### Changed
- **`sm_divergence.core` removed**; the kernel is the `sm-resolver` dependency.
  The top-level public API is unchanged (`from sm_divergence import Corroborator,
  Finding, Resolver, Status, View, ViewT, diff_views, OMISSION, …` still work — now
  re-exported from `sm-resolver`). Deep imports of `sm_divergence.core.*` no longer
  exist; import from `sm_resolver` or the top level.
- CI installs the private `sm-resolver` git dependency (needs the
  `SM_RESOLVER_PAT` secret, or a public `sm-resolver`).
- Version realigned (pyproject had drifted at 0.3.0 while the package was at 0.5.0).

## [0.5.0] — 2026-07-04

Signed portable-identity self-description (Phase 3) — identity correspondence
becomes an agent-signed fact instead of caller-configured trust.

### Added
- **`sm_divergence.identity` self-description** — the agent signs a bundle
  asserting its own aliases (its name per namespace) and service endpoints with
  its `did:key`; a consumer verifies it offline and drives resolvers from the
  *verified* names, so a source contradicting a signed alias/endpoint diverges
  from the agent's own signature:
  - `build_self_description(aliases, services, private_key)` → signed
    `{descriptor, sig}` (did derived from the key; 24h default TTL).
  - `verify_self_description(bundle)` → `SelfDescription | None` (offline sig +
    freshness; string→string alias/service maps; never raises).
  - `verified_descriptions(bundles)` → verify a map, keep only what verifies.
  - `signed_alias_for(descriptions, namespace)` → a `did_for` / `locator_for`
    backed by verified aliases; **falls back to the id when unverified**, so a
    forged description can't redirect a resolver.
- **`sm_divergence._signing`** — the shared Ed25519 / `did:key` / JCS primitives,
  now used by both the discovery attestation adapter and the self-description
  (behind the `attestation` extra). No behaviour change to `verified_did`.

## [0.4.0] — 2026-07-04

The identity layer (Phase 2 of the resolver-stack design) — the core's second
consumer, proving the kernel generalizes past discovery. Corroborates the one
field that must agree across an agent's DID methods: its verification key.

### Added
- **`sm_divergence.identity`** — key-consistency across DID methods, built on
  the same core (`DidView` implements `View`; the resolvers produce it,
  `Corroborator` + `diff_views` do the rest):
  - `DidKeyResolver` — resolves a `did:key` offline (the self-certifying root);
  - `DidWebResolver` — fetches a `did:web` document and reads its
    `publicKeyMultibase`;
  - `UniversalResolverResolver` — resolves any method via a DIF Universal
    Resolver endpoint (`GET {base}/1.0/identifiers/{did}`).
  A method that serves a different key than the root `did:key` is a `key`
  divergence — the identity-layer analogue of endpoint tampering (a hijacked
  domain, a stale mirror, or a lying resolver). Keys compare as `did:key`
  multibase strings, so no crypto dependency is added.
- Public: `DidView`, `DidKeyResolver`, `DidWebResolver`, `UniversalResolverResolver`,
  `key_from_did_key`, `key_from_did_document`, `did_web_url`, `identity_did`, `KEY`.

## [0.3.0] — 2026-07-04

The core/discovery seam (Phase 1 of the resolver-stack design). Splits the
package into a source-agnostic **kernel** and the discovery **layer** on top, so
the kernel is extractable and a thin per-format adapter (e.g. a NANDA Index
adapter) needs no discovery internals.

### Added
- **`sm_divergence.core`** — the layer-agnostic kernel: the `View` contract
  (a claim reduced to named comparable fields via `comparable()`), a generic
  `Resolver[T]` protocol, a generic `diff_views` (findings named after whatever
  fields the view exposes), the `Corroborator[T]` orchestration, and `Finding`.
  Nothing here knows any registry format. Intended to extract as a standalone
  kernel once a second layer consumes it.
- **`sm_divergence.discovery`** — the registry-integrity layer: `RecordView`
  plus the `HttpByIdResolver` (NEST) and `NandaIndexV2Resolver` adapters, all
  thin on the core.
- `Corroborator`, `View`, `ViewT` are now public (for adapter/layer authors).

### Changed
- **Finding detail is uniform across layers.** A field divergence now carries
  `{"field": <name>, "values": {source: value}}` (was `{"endpoints": {...}}` /
  `{"dids": {...}}`), so any consumer parses findings the same way regardless of
  layer or field. `omission` detail is unchanged. `kind` is unchanged
  (`omission`, or the field name — `endpoint`/`did`).
- Module layout moved under `core/` and `discovery/`. The top-level public API
  (`from sm_divergence import …`) is unchanged; only deep imports
  (`sm_divergence.client`, `.resolver`, `.index_v2`, `.models`, `.attestation`)
  moved (to `sm_divergence.discovery.*`).

## [0.2.0] — 2026-07-04

Heterogeneous registries: corroborate across registries that speak *different*
formats, not just different JSON at the same by-id endpoint.

### Added
- **The `Resolver` protocol** (`sm_divergence.resolver`, SPEC §6) — a per-registry
  component mapping a canonical id to a normalized `(Status, RecordView)`. Each
  resolver owns one registry's transport, record extraction, and native
  verification; the diff is untouched because every resolver returns the same view.
- **`HttpByIdResolver`** — the `GET /api/agents/{id}` shape (e.g. NEST), the v0.1
  behavior repackaged as the first resolver.
- **`NandaIndexV2Resolver`** (`sm_divergence.index_v2`) — the NANDA Index v2 two-hop
  resolve (`/api/v1/resolve?locator=…` → `{registry_url, identifier}` → fetch the
  record), normalized to a `RecordView`. `locator_for` maps a canonical id to the
  Index's URN locator (identity correspondence is the caller's to define).
- **`DivergenceDetector` accepts `str | Resolver`** — bare URLs are wrapped in
  `HttpByIdResolver` (back-compatible), and resolver instances of different formats
  can be mixed in one detector. Views are keyed by each resolver's `label`.
- **CLI `--nanda-index URL`** — corroborate a NANDA Index v2 alongside `--registry`.

### Changed
- `looks_absent` (was `_looks_absent`) is now a shared public helper so every HTTP
  resolver classifies soft-404 identically.

## [0.1.0] — 2026-07-04

Initial public release of sm-divergence — cross-registry divergence detection for
accountable agent discovery.

### Added
- **The diff** (`diff_views`, SPEC §4) — the pure, deterministic core: per-registry
  claims → `omission` / `endpoint` / `did` findings. No I/O; an unreachable
  registry (an `error` claim) is excluded rather than counted as absence.
- **Claim classification** (`fetch_view`, SPEC §3) — one registry's answer about one
  id as `present` / `absent` / `error`, with hard-404 and soft-404 (`200` + not-found
  body) both mapping to `absent`. Injectable by-id path and record adapter.
- **`DivergenceDetector`** — fetch + diff + dedupe orchestration with an
  `on_finding` callback that fires once per distinct finding; `check_once` one-shot.
- **Verified-DID extraction** (`sm_divergence.attestation`, SPEC §5) — optional
  `attestation` extra: Ed25519 / `did:key` / JCS verification of a self-certifying
  record, plus a subject-match guard, feeding the `did` diff. Kept out of the core
  so omission/endpoint checks carry no cryptographic dependency.
- **CLI** — `python -m sm_divergence check --registry … --watch …`; exit `2` on any
  divergence (cron/CI-friendly), `--json`, `--attestation`.
- Whitepaper, spec, and governance documents.
