# Corroboration Divergence — Detection Procedure

**Spec version:** `divergence/0.4-draft`
**Status:** DRAFT / Working Draft
**Version identifier (wire):** `divergence/0.3`
**Last edited:** 2026-10-30
**Signing/identity substrate (optional):** JCS canonicalization, Ed25519, `did:key` — the convention shared across the `sm-*` family.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted as in RFC 2119.

This procedure is specified normatively in the IETF draft *Multi-Source
Corroboration for AI Agent Discovery*
(`draft-chandra-agent-registry-corroboration-00`); `sm-divergence` is that
draft's reference implementation. Parenthesised `draft §N` citations below point
at the corresponding draft section. **CORR-DIGEST** is `lowercase-hex(SHA-256(JCS(v)))`; values in
digest-bearing fields MUST NOT be JSON floats.

---

## 1. Introduction

A consumer that reaches an agent through more than one **source** — two
registries, two DID methods, two catalogs — can detect a cheating source by
comparing what each claims. This document specifies that comparison: how one
source's claim about one agent is classified, how a claim is reduced to a
comparable **view**, and how views across sources are diffed into findings.

The procedure is source-, format-, and layer-agnostic. It fixes the *decision
procedure* (claim classification, the view contract, the diff) normatively and
treats the byte-level fetch as an injectable detail, because the value is in the
diff, not the wire format. The same procedure serves a **discovery** layer
(comparing registries about an agent's endpoint) and an **identity** layer
(comparing DID methods about an agent's key); §7 gives both.

### 1.1 Scope

Owns:

- The **claim classification** for one source × vantage × agent: `present`,
  `absent`, or `error` (§3).
- The **view contract** — how a present claim is reduced to comparable fields,
  with canonicalization (§4).
- The **diff** turning claims into `omission`, `source_equivocation`, and
  per-field findings, with confirmation (§5).
- The **verdict** per subject and the signed **Corroboration Record** (§6, §9).

Does NOT own: the source itself; the record/document format or its signing (a
consumer supplies a resolver that maps a source answer to a view); remediation or
policy on a finding; and any append-only/witnessed transparency log.

### 1.2 Why a separate procedure

Tampering is defeated by self-certifying records — an orthogonal mechanism that
verifies the *content* of a served artifact. Omission and equivocation cannot be
defeated that way (a withheld artifact has no signature; two equivocating
artifacts are each individually valid), so they require a distinct procedure —
comparison across sources — with a distinct failure mode and distinct evidence.

## 2. Terminology

| Term | Meaning |
| --- | --- |
| **Source** | Anything that answers "what do you have for agent *X*?" — a registry, a DID method, a catalog. |
| **Vantage** | A network perspective a source is observed from (a region, a resolver instance); MAY be `null`. Preserved as a distinct axis from *source* (draft §3). |
| **Watch set** | The agent ids a consumer compares across sources. |
| **Claim** | One source's answer about one agent from one vantage at one instant: `(source, vantage, status, view, observed_at)`, classified `present`/`absent`/`error` (§3). |
| **View** | The comparable reduction of a present claim: named string fields via `comparable()` (§4). |
| **Resolver** | The per-source adapter: canonical id → `(Status, View)` (§6). MAY expose a `vantage`. |
| **Corroborator** | The orchestration: resolve all (source, vantage), diff, confirm, and return a verdict per subject (§6). |
| **Finding** | One detected disagreement: `{kind, agent_id, confirmation, detail}` (§5). |
| **Verdict** | A subject's sweep outcome: `AGREE`, `DIVERGENT`, or `INSUFFICIENT` (§6). |

## 3. Classifying one source's claim

For a source *S* and agent *A*, a consumer MUST resolve exactly one of:

- **`present`** — *S* served a claim for *A*, reduced to a view (§4).
- **`absent`** — *S* positively asserts *A* is unknown. A consumer MUST treat an
  HTTP `404` as `absent`, and SHOULD treat a `200` whose body positively signals
  not-found (e.g. `{"success": false}`, or an `error` containing "not found") as
  `absent` (the "soft-404" some sources return).
- **`error`** — any other outcome: connection failure, timeout, non-`404` error
  status, unparseable body, or an answer the resolver cannot map to a view.

An `error` claim MUST be excluded from the diff (§5) entirely. It is NOT `absent`.
This is normative and central: **a source that failed to answer has asserted
nothing, and MUST NOT be treated as claiming the agent is absent** — otherwise
every transient fault becomes a false omission.

## 4. The view contract

A `present` claim MUST be reduced to a **view**: an object exposing
`comparable() → Mapping[field_name, str | None]`. The map's keys are the fields
that participate in the diff; a value of `None` never participates (an
unverifiable or missing field is not a disagreement). The view type is the
layer's choice — discovery uses `RecordView{endpoint, did}`, identity uses
`DidView{key}` — and the diff (§5) is identical regardless.

**Canonicalization (draft §5).** A layer MUST canonicalize a field before it
enters the view, so two references to the same resource compare equal. For
URI-valued fields (e.g. `endpoint`) an implementation MUST apply RFC 3986 §6
syntax-based normalization — lowercase scheme and host, drop the scheme's default
port, empty path → `/`. For key-valued fields the `did:key` multibase form is the
comparison encoding. Where a field carries its own proof (a signed record's `did`,
a key), the resolver MUST populate it only from a verified artifact whose subject
binds to the outer id; on any verification failure the field is `null`, and an
unverified value MUST NOT produce a divergence against a verified one
(no-laundering).

## 5. The diff

Input is the set of claims for one agent in one sweep (each a `(source, vantage,
status, view, observed_at)` tuple). `error` claims contribute nothing. For each
id in the watch set:

### 5.1 `omission`

Emit an `omission` finding iff the id is `present` on ≥1 source AND `absent` on
≥1 other. Both sides MUST be positive claims; an `error` (no-claim) source
contributes to neither. Detail: `{present_on, missing_from}` (sorted source
lists).

### 5.2 `source_equivocation` (draft §6.3)

For each source observed from more than one vantage, if that source's vantages
yield differing non-`None` values for a field, emit a `source_equivocation`
finding attributing that source. Detail: `{source, field, values}` where `values`
maps vantage labels to values. A source under `source_equivocation` for a field
contributes **no** single agreed value to §5.3 for that field (a source that
disagrees with itself cannot corroborate); its per-vantage values are retained for
audit.

### 5.3 Field divergence

For each field name appearing in any present view's `comparable()`, take each
non-equivocating source's value agreed by its vantages. Emit a finding of `kind =
<field name>` iff more than one distinct value appears **across sources**. Detail
is uniform: `{"field": <name>, "values": {source: value}}`. Thus discovery yields
`endpoint` / `did` findings and identity yields `key` findings, from the same code.

### 5.4 Determinism

The diff MUST be pure: deterministic ordering, no I/O, no raising. A single id
MAY produce multiple findings (e.g. an `omission` and a field divergence).

### 5.5 Confirmation (draft §7)

Every claim carries `observed_at` (epoch seconds). Every finding carries a
`confirmation` state: **`suspected`** on first observation, **`confirmed`** once
re-observed in a later sweep whose `observed_at` exceeds the first observation by
at least the deployment's configured **staleness window** (derived from the
sources' propagation characteristics). The window absorbs legitimate propagation
lag; only persistent disagreement is confirmed. Confirmation is evaluated
deterministically from recorded timestamps — no external clock — and a finding's
dedup fingerprint MUST exclude `confirmation`. Consumers SHOULD treat `suspected`
as a monitoring signal and `confirmed` as evidence.

## 6. Resolver and Corroborator

A **Resolver** hides one source's wire format: given a canonical agent id it
performs *that* source's query, applies *that* source's native verification, and
returns `(Status, View)` (§3–4). A resolver MUST NOT raise — an unreachable or
unparseable source is `error` (§3), never a false `absent` — and carries a stable
`label` naming the source in findings. Because every resolver returns a view,
§5's diff is unchanged by format heterogeneity; resolvers of different formats
MAY be compared in one run.

A **Corroborator** takes two or more resolvers, resolves each watch id against
each `(source, vantage)`, applies §5, and returns one result per subject: a
**verdict** and the claims (with `error` claims retained for audit) and findings.
Resolvers are deduped by `(label, vantage)`. The verdict is **`INSUFFICIENT`**
when fewer than two decisive (`present`/`absent`) claims exist (nothing to
corroborate — a Corroborator MUST NOT report agreement in that case),
**`DIVERGENT`** when any finding is present, else **`AGREE`**. It SHOULD
deduplicate emitted findings by a stable fingerprint over `{kind, agent_id,
detail}`, so a persisting divergence notifies once while still appearing in each
check's full result.

## 7. Layer instantiations (reference)

### 7.1 Discovery layer — `RecordView{endpoint, did, digest}` + lease position

The compared fields are `endpoint`, `did`, and `digest`. The view also carries a
**lease position** — `sequence` and `sequence_scope` — exposed through
`binding()` per kernel SPEC §3b, and an `authority_issuer` for the record. None
of those three is compared: two registries validating the same subject through
different issuers is the ordinary multi-registry case, and a sequence is only
meaningful within one issuer's scope. The kernel's supersession rule (kernel
SPEC §4e) uses the position to attribute a lagging registry as `stale_binding`
and withhold its superseded target from the field comparison.

- **Known-subject resolver** — the registry-assisted resolution profile for a
  Known Subject without a usable DNS Discovery Anchor (`known-subject-resolution-02`),
  one hop:
  1. `POST {base}/resolve` with `{identity, identityType, maxResults,
     acceptedMethods}`; the request MUST NOT carry intent, capability query, or
     a next-registry field;
  2. `200` with `targets: []` → `absent`; `404` → `absent`; a 4xx Problem
     Details (`RFC 9457`) `code` → `error` with the outcome it maps to
     (`unverifiable` / `revoked` / `stale` → `unverifiable`, `revoked`,
     `expired`; `policy-rejected`, `unsupported-target` → `refused`;
     `malformed-response` → `unparseable`); 5xx/transport → `error`;
  3. one Resolution Target Object is selected (default: first non-`fallback`
     target of an accepted method); a target whose `method` was not accepted —
     in particular another registry, which the profile forbids as a terminal
     target — is `error`/`refused`;
  4. a target past `expiresAt`, or lacking it, or lacking `sequence`, is
     `error` (`expired` / `unverifiable`) — a binding the profile says MUST be
     treated as stale is not a claim of absence;
  5. `targetUrl` → `endpoint`; `targetDigest` → `digest`; `sequence` and
     `authority.issuer` → the lease position. No `did`: Authority Evidence is
     not an agent-signed record.
  Optionally the response's `registry.id` MUST equal the configured expected
  identity, else `error`/`unverifiable`: provenance from a registry other than
  the one configured is not a claim by the one configured. The resolver never
  evaluates Authority Evidence (§10) and never fans out; one instance is one
  configured registry.
- **By-id resolver** — `GET {base}/api/agents/{id}` (path injectable), classified
  per §3, endpoint read from a top-level field.
- **NANDA Index v2 resolver (legacy)** — a two-hop pointer resolve, kept for
  registries still exposing it. Under the known-subject profile a registry
  returns a terminal target and never another registry, so an index is one
  registry among several and this shape is not used:
  1. `GET {index}/api/v1/resolve?locator={locator}` → `{registry_url, identifier}`
     (`404`/soft-404 → `absent`; missing/empty fields → `error`);
  2. `GET {registry_url}{record_path}` (default `/agents/{identifier}`) → the
     record, classified and mapped per §3–4.
  The canonical id maps to the Index locator via a caller-supplied `locator_for`.
- **Verified-DID extraction (optional)** — the `did` field is populated only from
  a *proven* self-certifying record, so it is meaningful across sources:
  1. the record carries `{record, sig}` where `record` has a `did:key` and the
     attested fields;
  2. decode the Ed25519 key from the `did:key` (multicodec `0xED01` + 32-byte
     key, base58btc, `did:key:z…`);
  3. verify `sig` (base64) over the JCS-canonical (`RFC 8785`) `record`;
  4. on any failure, or a non-Ed25519 DID, contribute **no** `did`;
  5. a consumer SHOULD require the attestation subject (`record.agent_id`) to
     equal the outer id — a source MUST NOT dress agent *B*'s record in *A*'s
     valid attestation.
  This is offline: a `did:key` *is* the key, so the (possibly hostile) source
  endpoint is never contacted to verify.

### 7.2 Identity layer — `DidView{key}`

The compared field is the agent's Ed25519 verification key, in `did:key`
multibase form (`z…`) — the encoding both `did:key` DIDs and
`Ed25519VerificationKey2020` `publicKeyMultibase` use, so keys compare as strings
with no decoding.

- **`did:key`** — resolved offline: the key is the multibase after the prefix.
  The self-certifying root of truth.
- **`did:web`** — fetch the document (`https://{domain}/.well-known/did.json`, or
  path-mapped), read the first Ed25519 `publicKeyMultibase`. `404` → `absent`.
- **Universal Resolver** — `GET {base}/1.0/identifiers/{did}`; read the key from
  the returned `didDocument`.

A method that serves a different key than the root `did:key` for the same agent
is a `key` divergence. The canonical id maps to each method's DID via a
caller-supplied `did_for` — the identity-correspondence input (§8).

## 8. Portable-identity self-description (optional)

Corroboration across differently-named sources requires knowing that each
source's name refers to the same agent — *identity correspondence*. The
procedure cannot infer it; §7's resolvers take it as a caller-supplied mapping
(`locator_for` / `did_for`). A **self-description** lets that mapping be
*proven* instead of trusted: the agent signs a bundle asserting its own aliases
and service endpoints with its `did:key`.

Bundle (draft §8 — a flat object; `signature` is a member, over the JCS of every
other member):

```
{
  "version": "self-description/0.1",
  "subject": "did:key:z…",          // the signer's did:key
  "seq": 7,                          // monotonic counter
  "aliases":   { "<namespace>": "<name>", … },
  "endpoints": [ "<uri>", … ],
  "signature": "<base64 Ed25519 over JCS of all other members>"
}
```

Verification:

1. `version` MUST equal `self-description/0.1`; `seq` MUST be an integer (not a bool);
2. decode the Ed25519 key from `subject`;
3. verify `signature` (base64) over the JCS-canonical bundle **minus** `signature`;
4. `aliases` MUST be a string→string map, `endpoints` a list of strings.

There is no expiry: freshness is supersession by `seq` (§8.1), so verification is
offline (the `did:key` is the key) and consults no clock.

### 8.1 Supersession and agent equivocation

A signed description stays validly signed forever, so a source could replay a
superseded description. `seq` orders them: **the highest `seq` supersedes.** When
descriptions are collected from multiple sources (§8.2), a consumer MUST reconcile
by `seq`:

- among the descriptions at the highest observed `seq`, if two carry different
  JCS bytes (different `subject`/`aliases`/`endpoints`), the agent's own key
  signed two conflicting statements — **`agent_equivocation`** (key compromise or
  a lying agent). Correspondence MUST fail closed (no canonical description).
- a source presenting a description below the highest `seq` is **stale** (a
  `stale_description` signal); it does not override the winner.

`agent_equivocation` is the one finding the corroboration framework raises about
the *agent* rather than a source.

### 8.2 Distribution (the description is itself corroborated)

The description MUST NOT be trusted from a single source under test — that source
controls whether and which version is served (omission and replay apply to the
description too). A consumer SHOULD fetch it from every source and reconcile
(§8.1): a source that omits it (`omission`), serves a stale one, or serves an
unverifiable one (no claim) is surfaced rather than silently trusted.

### 8.3 Driving correspondence, and alias closure

A consumer SHOULD derive each resolver's per-source name from the canonical
description's `aliases`. A source whose name or endpoint contradicts it is then
diverging from the agent's own signature. Two rules bound this:

- **Fallback.** An absent, unverifiable, or equivocating description MUST fall
  back to the caller's mapping — a forged description MUST NOT redirect a resolver.
- **Closure.** A self-description proves the agent *claims* an alias, not that the
  named source agrees. A record fetched via a claimed alias that does not bind
  back to the same `did:key` MUST contribute **no claim** (never a divergence) —
  axiom "resolve FROM the identity, verify BACK to it", so a malicious agent
  naming a victim's alias cannot manufacture a divergence against the victim. The
  bind-back is layer-specific: discovery — the record's verified `did` equals the
  description's `subject`; identity — the resolved key equals the `subject`
  `did:key`'s key.

## 9. The Corroboration Record (draft §9)

An implementation SHOULD seal each sweep into a signed, content-addressed
**Corroboration Record** — one per `(sweep, subject)`, **whatever the verdict**.
A trail recording only disagreements cannot prove its checks ran; the `AGREE`
record is the positive attestation a downstream consumer binds.

```
{
  "version": "corroboration/0.4",
  "record_id": "<CORR-DIGEST of every member except record_id and signature>",
  "subject": { "agent_id": "<id>", "did": "<did:key or null>" },
  "observed_at": "<RFC 3339 UTC, Z>",
  "staleness_window_s": <integer>,
  "verdict": "AGREE" | "DIVERGENT" | "INSUFFICIENT",
  "claims":   [ { "source", "vantage", "status", "view", "outcome", "binding"? }, … ],
  "findings": [ { "kind", "agent_id", "confirmation", "detail" }, … ],
  "sweeper": "did:key:z…",
  "signature": "<base64 Ed25519 over JCS of all other members>"
}
```

Rules:

1. `record_id` MUST equal the CORR-DIGEST of the record minus `record_id` and
   `signature`; a verifier MUST recompute and compare.
2. `signature` MUST verify against the key `sweeper` encodes (offline). A record
   MAY additionally be anchored in an append-only transparency service; a consumer
   MUST NOT report that anchored tier without verifying an inclusion proof against
   a log key it trusts.
3. Count/window/time values are exact integers or strings; no JSON float appears.
4. `claims` MUST include `error`-status entries (excluded from the diff, retained
   for audit).
5. From `corroboration/0.4` a claim entry whose view exposes a lease position
   carries `binding: {sequence, scope}`. A `stale_binding` finding names the
   sequences it compared; the entries are where a verifier re-derives that
   comparison from recorded bytes. A record with no `binding` members reads as
   "no binding", which is the conservative interpretation, and earlier
   versions remain verifiable.

## 10. Ownership map (what this is *not*)

- **The record/document format and its signing** — the AgentFacts /
  self-certifying-record / DID-document layer. This procedure verifies (§7) but
  does not define or issue artifacts.
- **Tampering defense** — closed by self-certifying records, not by this.
- **A transparency log / witness network** — the stricter, stateful primitive for
  single-source consistent lying (out of scope; see WHITEPAPER).
- **Remediation policy** — what a caller does on a finding.

## 11. Conformance (corpus plan)

A conforming implementation MUST reproduce, for a fixed set of per-source claim
inputs, the exact finding set of §5 and verdict of §6, including: agreement →
`AGREE`, none; `present` + `absent` → `DIVERGENT`, `omission` with correct
`present_on`/`missing_from`; distinct cross-source field values → `DIVERGENT`, a
finding of that field's `kind` with `{field, values}`; a source's vantages
disagreeing → `DIVERGENT`, `source_equivocation` (and no spurious cross-source
divergence for that field); two spellings of one URI (RFC 3986) → none; a single
or identical field value → none; one verified value beside one `None` → none;
fewer than two decisive claims → `INSUFFICIENT`; `error`/unreachable source →
excluded (no `omission`); soft-404 → `absent`; one id → multiple simultaneous
findings where applicable. A sealed Corroboration Record (§9) MUST round-trip:
recomputed `record_id` and `signature` verify. The corpus is view-agnostic and
reused by every layer.

## 12. Deferred

- A quorum reducer over findings (*k*-of-*n* agreement) for >2 sources.
- Durable per-source divergence history (source reputation).
- A normative wire schema for a shareable `Finding` (cross-tool interchange).
