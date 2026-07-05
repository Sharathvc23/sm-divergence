# Governance

## Scope

| In scope | Out of scope |
| --- | --- |
| the claim classification (`present`/`absent`/`error`), the view contract (`comparable()`), the divergence diff (`omission` + per-field: `endpoint`/`did`/`key`/…), and the optional verified-DID extraction | the source itself; the record/document format and its signing (AgentFacts / self-certifying records / DID documents — the *tampering* half); a transparency log or witness network (single-source consistent lying); remediation policy on a finding; and each source's transport/schema (injected by a resolver) |

The primitive owns one thing — answering *"do these sources disagree about this
agent, and how?"* — across any layer (discovery, identity, and future
capability/evidence). Anything outside the table belongs to a companion package
or the caller.

## Versioning

Semantic Versioning 2.0.0. The claim classification (SPEC §3), the view contract
(SPEC §4), and the diff (SPEC §5) are frozen within a major; a change requires an
RFC-style PR to `SPEC.md` before code. The library API (`diff_views`,
`Corroborator`, `DivergenceDetector`, `check_once`) follows the same major.

## Conformance

An implementation is conforming iff it reproduces the finding set in SPEC §10 for
the specified claim inputs. The diff is pure and deterministic by construction, so
conformance is mechanical.

## Changes

Spec-affecting changes: open a PR editing `SPEC.md` (and `WHITEPAPER.md` if the
rationale moves), then the implementation and tests. Non-spec changes (adapters,
CLI, performance) are ordinary PRs against a green `make ci-local`.
