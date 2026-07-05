# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and this project adheres to
[Semantic Versioning](https://semver.org/).

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
