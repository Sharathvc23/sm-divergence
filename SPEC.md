# Corroboration Divergence — Detection Procedure

**Spec version:** `divergence/0.2-draft`
**Status:** DRAFT / Working Draft
**Version identifier (wire):** `divergence/0.2`
**Last edited:** 2026-07-04
**Signing/identity substrate (optional):** JCS canonicalization, Ed25519, `did:key` — the convention shared across the `sm-*` family.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY are to be interpreted as in RFC 2119.

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

- The **claim classification** for one source × one agent: `present`, `absent`,
  or `error` (§3).
- The **view contract** — how a present claim is reduced to comparable fields (§4).
- The **diff** turning per-source claims into `omission` and per-field findings (§5).

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
| **Watch set** | The agent ids a consumer compares across sources. |
| **Claim** | One source's answer about one agent, classified `present`/`absent`/`error` (§3). |
| **View** | The comparable reduction of a present claim: named string fields via `comparable()` (§4). |
| **Resolver** | The per-source adapter: canonical id → `(Status, View)` (§6). |
| **Corroborator** | The orchestration: resolve all sources, diff, emit (§6). |
| **Finding** | One detected disagreement: `{kind, agent_id, detail}` (§5). |

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

## 5. The diff

Input is a mapping `views[source][agent_id]` where each entry is a view
(present), `null` (absent), or *absent from the mapping* (the `error` case — no
claim). For each id in the watch set:

### 5.1 `omission`

Emit an `omission` finding iff the id is `present` on ≥1 source AND `absent` on
≥1 other. Both sides MUST be positive claims; an `error` (no-claim) source
contributes to neither. Detail: `{present_on, missing_from}` (sorted source
lists).

### 5.2 Field divergence

For each field name appearing in any present view's `comparable()`, collect the
non-`None` values keyed by source. Emit a finding of `kind = <field name>` iff
more than one distinct value appears. Detail is uniform: `{"field": <name>,
"values": {source: value}}`. Thus discovery yields `endpoint` / `did` findings
and identity yields `key` findings, from the same code.

### 5.3 Determinism

The diff MUST be pure: deterministic ordering, no I/O, no raising. A single id
MAY produce multiple findings (e.g. an `omission` and a field divergence).

## 6. Resolver and Corroborator

A **Resolver** hides one source's wire format: given a canonical agent id it
performs *that* source's query, applies *that* source's native verification, and
returns `(Status, View)` (§3–4). A resolver MUST NOT raise — an unreachable or
unparseable source is `error` (§3), never a false `absent` — and carries a stable
`label` naming the source in findings. Because every resolver returns a view,
§5's diff is unchanged by format heterogeneity; resolvers of different formats
MAY be compared in one run.

A **Corroborator** takes two or more resolvers, resolves each watch id against
each, builds the `views` mapping, and applies §5. Fewer than two sources → no-op
(nothing to corroborate). It SHOULD deduplicate emitted findings by a stable
fingerprint over `{kind, agent_id, detail}`, so a persisting divergence notifies
once while still appearing in each check's full result.

## 7. Layer instantiations (reference)

### 7.1 Discovery layer — `RecordView{endpoint, did}`

- **By-id resolver** — `GET {base}/api/agents/{id}` (path injectable), classified
  per §3, endpoint read from a top-level field.
- **NANDA Index v2 resolver** — a two-hop pointer resolve:
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

Bundle: `{descriptor, sig}` where `descriptor` carries `v`, `did` (the signer's
`did:key`), `seq` (a monotonic counter), `aliases` (namespace → the agent's name
there), `services` (kind → endpoint), `issued_at`, `expires_at`. Verification:

1. decode the Ed25519 key from `descriptor.did`;
2. verify `sig` (base64) over the JCS-canonical `descriptor`;
3. reject if `now > expires_at`; `seq` MUST be an integer (not a bool);
4. `aliases` and `services` MUST be string→string maps.

Verification is offline (the `did:key` is the key).

### 8.1 Supersession and agent equivocation

A signed description stays validly signed forever, so freshness alone (`expires_at`)
does not prevent a source from replaying a superseded description within its
window. `seq` orders them: **the highest `seq` supersedes.** When descriptions are
collected from multiple sources (§8.2), a consumer MUST reconcile by `seq`:

- among the descriptions at the highest observed `seq`, if two carry different
  substantive content (different `did`/`aliases`/`services`), the agent's own key
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
  description's `did`; identity — the resolved key equals the `did:key`'s key.

## 9. Ownership map (what this is *not*)

- **The record/document format and its signing** — the AgentFacts /
  self-certifying-record / DID-document layer. This procedure verifies (§7) but
  does not define or issue artifacts.
- **Tampering defense** — closed by self-certifying records, not by this.
- **A transparency log / witness network** — the stricter, stateful primitive for
  single-source consistent lying (out of scope; see WHITEPAPER).
- **Remediation policy** — what a caller does on a finding.

## 10. Conformance (corpus plan)

A conforming implementation MUST reproduce, for a fixed set of per-source claim
inputs, the exact finding set of §5, including: agreement → none; `present` +
`absent` → `omission` with correct `present_on`/`missing_from`; distinct field
values → a finding of that field's `kind` with `{field, values}`; a single or
identical field value → none; one verified value beside one `None` → none;
`error`/unreachable source → excluded (no `omission`); soft-404 → `absent`; one
id → multiple simultaneous findings where applicable. The corpus is view-agnostic
and reused by every layer.

## 11. Deferred

- A quorum reducer over findings (*k*-of-*n* agreement) for >2 sources.
- Durable per-source divergence history (source reputation).
- A normative wire schema for a shareable `Finding` (cross-tool interchange).
