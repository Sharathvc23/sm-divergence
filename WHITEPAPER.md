# Corroboration for Accountable Discovery — Whitepaper

*Personal research contribution by [Stellarminds.ai](https://stellarminds.ai), aligned with [Project NANDA](https://projectnanda.org) standards.*

> The procedure described here is specified normatively in the IETF draft
> *Multi-Source Corroboration for AI Agent Discovery*
> (`draft-chandra-agent-registry-corroboration-00`); `sm-divergence` (with the
> `sm-resolver` kernel) is its reference implementation.

---

## Abstract

Agents reach each other through middlemen — registries, name services, DID
methods, catalogs — and a middleman can lie: it can serve a tampered endpoint,
hide an agent that is actually registered, or answer different clients
differently. Signing an artifact defeats *tampering* — a self-certifying record
cannot be altered without breaking its signature — but **no signature on an
artifact can prove what a source chose *not* to serve.** Omission and
equivocation are invisible to a single source. This paper describes the cheap,
robust defense that a federated agent internet already makes available:
**corroboration.** If an agent is reachable through two or more sources, a
consumer can ask all of them the same question and treat any disagreement as a
signal. It further shows that corroboration is not a discovery gadget but a
*reusable primitive* — a per-source resolver that normalizes any format to one
comparable view, plus a pure diff — that recurs at every discovery-adjacent
layer and is anchored, at each, to a portable identity. `sm-divergence`
implements this primitive as a small source-agnostic kernel with two layers on
it today: discovery (registries) and identity (DID methods).

---

## 1. Problem

Discovery in an open agent network is not one lookup against one authority; it is
a lookup against whichever source a client happens to use. That is the design
goal — no central directory, no single point of control or failure — and it is
also the exposure. Every source in the mesh is a place where the answer can be
wrong, and the client has no independent way to know.

Three distinct lies:

- **Tampering** — the source serves an artifact whose contents it altered
  (a redirected endpoint, a substituted key).
- **Omission** — the source silently drops an agent from its answers. The agent
  is registered; this source acts as though it is not.
- **Equivocation** — the source serves answer *A* to one client and *B* to
  another, so no single client sees the contradiction.

Self-certifying artifacts — a signed record or DID document a consumer verifies
offline — fully close **tampering**. They do nothing for the other two, and
cannot in principle: a signature attests the *content* of an artifact that was
served, never the *set* of artifacts withheld, nor the *consistency* of what was
shown across clients. A source that omits produces no artifact to verify; a
source that equivocates produces two individually-valid artifacts. The gap is
structural, and it is exactly the gap that decentralization opens.

Crucially, this is not unique to registries. The same three lies are available to
a *name service* about which key owns an agent, to a *DID method* about an
agent's verification key, to a *catalog* about an agent's capabilities. The
exposure is a property of *being a middleman*, so its defense should be a
property of the middleman layer in general — not a one-off per format.

## 2. Design axioms

These are consequences of the threat model, not preferences.

1. **Corroborate, don't trust.** An artifact proves its own contents; it cannot
   prove the source served it honestly or served it to everyone. The minimum unit
   of accountability is therefore *two independent sources*, not one better-signed
   source. With a single source there is nothing to check, and the primitive says
   so (it is a no-op) rather than manufacturing false assurance.

2. **A timeout is not a claim.** An unreachable source has asserted nothing — it
   is neither present nor absent. Silence must never be counted as omission, or
   the detector floods operators with false alarms during every network blip and
   trains them to ignore it. It fails *open*: an error excludes that source from
   the comparison for that cycle. *Consequence:* omission requires a *positive*
   claim of absence set against a *positive* claim of presence elsewhere.

3. **Only proven values disagree.** When comparing a field that carries its own
   proof (a signed record's DID, a `did:key`'s key), an unverifiable claim
   contributes nothing. One valid record plus one forged one is not a conflict
   between two authorities — the forged one is dropped before the comparison, so
   it can never be laundered into a "divergence" that discredits the honest source.

4. **Detect; do not remediate.** The primitive reports *that* sources disagree
   and *how*. What to do about it — alert, quarantine, prefer a source, page a
   human — is policy that belongs to the caller. Fusing detection to a fixed
   response would make the tool wrong for every deployment whose policy differs.

5. **A declaration annotates; it never absolves.** A source may publish, in
   advance, that it varies a field by context (§6). Where it has, the finding is
   *marked* as declared and still emitted, with the verdict unchanged. This is
   axiom 4 restated for declarations: deciding whether a declared divergence is
   acceptable is exactly the policy judgement axiom 4 refuses to make. It also
   keeps the source's own commitment in the record, which is what makes the
   opposite case — varying *contrary* to what was declared — a finding at all.

## 3. The primitive: resolve · view · diff

Corroboration factors into three pieces, and only the first is format-specific:

- **Resolve** — a per-source *resolver* performs that source's query (an HTTP
  by-id GET, a two-hop Index resolve, a DID-document fetch, a DNS lookup),
  applies that source's native verification, and normalizes the answer to a
  *view*. This is the only piece that knows a wire format; it is where a *thin
  adapter* lives.
- **View** — the comparable reduction of a claim to named fields
  (`comparable() → {field: value}`). A `None` value never participates: an
  unverifiable field is not a disagreement (axiom 3).
- **Diff** — a pure function over the views from all sources. It emits `omission`
  (present on one, positively absent on another) and one finding per view field
  whose non-`None` values disagree. Comparison is scoped to a *cohort* — the
  claims sharing one observation context — which matters only where a source has
  declared that it varies (§6); otherwise one cohort spans every claim. It never
  learns what layer it is serving.

Because the diff operates on normalized views, it is untouched by format
heterogeneity: a claim from a NEST-style registry and a claim from a two-hop
Index are compared identically once each is a view. This is what lets sources of
*different formats* be corroborated in one run, and what lets the *same* diff
serve a completely different layer.

## 4. The resolver stack

The primitive generalizes into a small source-agnostic **kernel** — the
`Resolver` protocol, the `View` contract, the diff, the orchestration, the
finding type — with a **layer** on top for each thing a middleman can be asked.
Each layer supplies its own view and its thin resolvers; nothing else changes.

```
                    portable identity  (a did:key — the invariant subject)
                             │  resolve FROM it · verify BACK to it
      ┌──────────────────────┼──────────────────────┬─────────────────────┐
      ▼                      ▼                       ▼                     ▼
  IDENTITY               DISCOVERY               CAPABILITY            EVIDENCE
  did:key/web/uni        registries              agent-facts /         receipts /
      │                  (NEST · Index)          cards / manifests     credentials
      ▼                      ▼                       ▼                     ▼
  DidView{key}          RecordView{endpoint,did}  (view)                (view)
      └──────────────────────┴──────── diff ───────┴─────────────────────┘
                                    │
                                    ▼
              divergence findings at every layer, each bound to the identity
```

Two layers run on the kernel today:

- **Discovery** — `RecordView{endpoint, did}`, with a by-id registry resolver
  (NEST) and the NANDA Index two-hop resolver. Catches a registry that omits an
  agent, serves a tampered endpoint, or (via verified attestation) binds a
  different DID.
- **Identity** — `DidView{key}`, with `did:key` (resolved offline — the
  self-certifying root of truth), `did:web` (fetched), and a Universal Resolver
  adapter. Catches a DID method that serves a different verification key than the
  root `did:key`: a `key` divergence, the identity analogue of endpoint tampering
  — a hijacked domain, a stale mirror, a lying resolver.

Capability (agent-facts / cards / manifests) and evidence (receipts /
credentials) are the same shape: a view and thin resolvers on the same kernel.

## 5. Anchoring to a portable identity

Every layer is *about the same agent*, and the only invariant across all of them
— across formats, sources, namespaces — is the key. A portable `did:key` is the
subject a discovery record points to, the document an identity method resolves,
the signer of a self-certifying record. So `resolve` and `verify` are the same
act seen twice: map format→view, then check the view is bound to the identity.
Corroboration at any layer is that recipe run across N sources.

This also frames the one thing corroboration cannot infer on its own: **identity
correspondence.** The same agent is a bare id on one registry, a URN locator on
another, a `did:web` on a domain. To compare, a consumer must map its canonical
id to each source's name (a `locator_for` / `did_for`).

A **signed self-description** turns that mapping from configuration-to-be-trusted
into an agent-signed fact. The agent signs a small bundle — a monotonic `seq`,
its aliases (its name in each namespace), and its service endpoints — with its
`did:key`; a consumer verifies it offline (the `did:key` *is* the key) and derives
each resolver's per-source name from the *verified* aliases. Correspondence is
then proven, and the check upgrades: a source whose name or endpoint contradicts
the signed description is diverging from the agent's *own signature*.

Three rules make it safe against the artifact's own failure modes. **Replay:** a
signed description stays signed forever, so `seq` supersedes — highest wins, and
the reconcile of descriptions gathered from every source yields the system's first
detection of **agent equivocation** (two valid descriptions at the same `seq` with
different content — a compromised or lying key), on which correspondence fails
closed. **Distribution:** the description is corroborated like everything else —
fetched from every source, so one that omits or replays it becomes an ordinary
finding, not a silent poisoning. **Closure:** a description proves the agent
*claims* an alias, not that the source agrees, so a record reached via a claimed
alias that does not bind back to the same `did:key` contributes no claim, never a
divergence — a malicious agent naming a victim's alias cannot manufacture a
divergence against the victim (axiom 3, extended to correspondence). With those,
the self-description is the artifact that anchors the stack: hand over the
`did:key`, verify one signature, and the agent tells you — provably — where it is
under every name.

## 6. Declared variation

Not every difference between two sources is misbehavior. A registry under a
data-residency obligation serves a different endpoint in one region than in
another, by design and often by law. A primitive that reports every such
difference as equivocation fires on normal operation, and a detector that fires
on normal operation gets switched off — which costs more than the false
positives did.

An **Answer Scope** is a source-signed bundle declaring, in advance, which fields
it varies and along which context class. It declares an *axis*, never a mapping.
"`endpoint` varies by region" is checkable: a verifier goes to another region and
looks. "EU callers get X" would be a promise about values made by the party doing
the varying, and a promise adds a label to a finding without adding any way to
test it.

Three constraints do the work, and each closes a way the mechanism could become a
blanket excuse:

- **The context must be occupiable.** A verifier must be able to construct it and
  repeat the observation. Region and network are occupiable. Caller identity,
  tenant, and subscription tier are not — a declaration about one could only be
  believed, and a corroborator that credited it would be reporting the source's
  own assertion back as evidence.
- **The declaration must be bound to the source that made it.** A valid signature
  proves only that *some* operator wrote the bundle; serving it at the source's
  own label is what demonstrates control of that label. Both are required.
- **No catch-alls.** Wildcards are refused, a field may be declared once, and the
  number of declared fields is bounded. The permissive form of a declared-scope
  mechanism is what turns it into an attack surface.

Declaring *nothing* is also a statement, and a different one from silence. An
empty scope asserts that the source does not vary; publishing nothing is
ambiguous between "does not vary" and "has never implemented this".

### What it does not settle

The party declaring the variation is the party exhibiting it. In the deployed
mechanisms this design borrows from, that is not so — a parent zone, a parent
certificate authority, or a standards body sets the tolerance. Occupiability is
the structural answer: a declaration on an axis a verifier can occupy is
falsifiable by observation, which is why non-occupiable axes are refused outright
rather than discouraged. A residual remains — a source that can tell it is being
corroborated can serve the corroborator the declared answer and everyone else
something else — and it is the same residual as single-source first contact (§8),
with the same eventual answer.

## 7. NANDA alignment

Project NANDA organizes the internet of agents into four pillars — **DNS**
(discovery), **CA** (identity), **Orchestration**, **Attestation**.
Corroboration is a DNS-and-CA-pillar primitive: it protects the integrity of
*discovery and identity resolution themselves*.

The alignment is more than a label. NANDA's discovery layer is multi-source *by
design* — a lean Index that delegates to a quilt of registries rather than a
single directory — and corroboration is only *possible* because of it. The
redundancy NANDA builds for resilience doubles as an integrity check: the same
quilt that removes the single point of failure removes the single point of
*trust*. `sm-divergence` turns that latent property into an active one, and is a
concrete mechanism behind **accountable discovery** — the claim that a federated
registry is not merely decentralized but *auditable*, that a participant can
catch a source lying rather than having to trust it.

## 8. Open questions

- **Single-source first contact.** Corroboration catches a source that disagrees
  with its peers. It cannot catch a *single* source lying *consistently* to a
  client who has never seen the agent elsewhere — there is nothing to compare
  against. Closing that last mile is transparency-log territory (an append-only,
  witnessed log of what each source served over time), a stricter and stateful
  primitive deliberately out of scope here.
- **Proof that a declaration came first.** An Answer Scope carries a monotonic
  sequence number, which orders declarations against each other but not against
  an observation. A source that is caught can still sign a declaration
  afterwards. Establishing that a declaration existed *before* the divergence it
  covers needs a witnessed record of what was published when — the same
  transparency-log territory as single-source first contact, and unsolved here
  for the same reason.
- **Quorum across many sources.** With more than two sources, a threshold policy
  (*k*-of-*n* agree) is more robust than pairwise disagreement; the diff surfaces
  every pairwise split today, and a quorum reducer is a natural layer above it.

---

## License

[MIT](LICENSE).
