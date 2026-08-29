# sm-divergence — catch a cheating registry by corroboration

**Integrity for the sources agents resolve through. A registry (or a name
service, or a DID method) can lie by omission, tampering, or equivocation;
signing an artifact closes only tampering. This asks several sources the same
questions and makes any disagreement loud.**

Agents reach each other through middlemen — registries, indexes, DID methods —
and a middleman can lie:

- **tamper** — serve a false endpoint (or key) for an agent,
- **omit** — hide an agent that is actually registered,
- **equivocate** — tell different clients different things.

A self-certifying artifact (a signed AgentFacts-style record, a `did:key`)
defeats tampering — it can't be altered without breaking its signature. But *no
signature can prove what a source chose **not** to serve.* Omission and
equivocation are invisible to a single source.

The cheap, robust defense is one decentralized discovery already hands you:
**corroboration.** If an agent is reachable through two or more sources, ask all
of them the same question and treat any disagreement as a signal. That is all
this library does — enough to turn a silently cheating source into a loudly
diverging one. See the [whitepaper](WHITEPAPER.md) for the argument and the
[spec](SPEC.md) for the normative procedure.

This is the **reference implementation** of the IETF Internet-Draft
[*Multi-Source Corroboration for AI Agent Discovery*](https://datatracker.ietf.org/doc/draft-chandra-agent-registry-corroboration/):
the [`sm-resolver`](https://pypi.org/project/sm-resolver/) kernel is the claim
model and diff, and this package is the signing layer — the agent
self-description and the signed
[Corroboration Record](#the-corroboration-record) — plus the reference discovery
and identity layers.

`-01` is the published revision. `-02` is prepared and is what this release
implements: it adds the claim-outcome vocabulary and requires a record to name
its signature algorithm. Both revisions and the diff between them are on the
datatracker, and the text of each is committed under [`draft/`](draft/),
byte-identical to what the IETF serves.

Requires Python 3.11 or later. The core has no cryptography dependency;
signing and verification live in the `attestation` extra, so you pull it only
when you use it.

> **Records carry their algorithm, bound to the key.** From
> `corroboration/0.3` a record names its signature algorithm, and a verifier
> derives the algorithm from the key type the sweeper's `did:key` encodes rather
> than trusting the record. Records issued at earlier versions carry no such
> member and remain verifiable.

> **Not a transparency log.** Corroboration catches a source that disagrees with
> its peers; it does not stop a *single* source lying *consistently* to a
> first-time caller. That last mile is transparency-log territory (WHITEPAPER §7).

## Where it fits

A **DNS/CA-pillar** primitive in the [Project NANDA](https://projectnanda.org)
four-pillar model (DNS / CA / Orchestration / Attestation): it protects the
integrity of *discovery and identity resolution themselves*. NANDA's discovery is
multi-source **by design** — a lean Index delegating to a quilt of registries —
and corroboration is only *possible* because of it: the redundancy built for
resilience doubles as an integrity check. This library turns that latent property
into an active one, the concrete mechanism behind **accountable discovery** — a
federated registry that is not merely decentralized but *auditable*.

## Install

```bash
pip install sm-divergence                 # omission + endpoint/key checks (httpx only)
pip install "sm-divergence[attestation]"  # + verified-DID checks (Ed25519/did:key)
```

## Quick start

```python
import asyncio
from sm_divergence import check_once

results = asyncio.run(check_once(
    ["https://registry-a.example", "https://registry-b.example"],
    ["agent-1", "agent-2"],
))
for r in results:
    print(r.agent_id, r.verdict)          # agent-1 DIVERGENT   (AGREE / DIVERGENT / INSUFFICIENT)
    for f in r.findings:
        print(" ", f.kind, f.confirmation, f.detail)
        # endpoint suspected {'field': 'endpoint',
        #                     'values': {'https://registry-a.example': 'https://real.example/',
        #                                'https://registry-b.example': 'https://attacker.example/'}}
```

Each `check` returns one `SweepResult` per subject — a **verdict** (`AGREE`,
`DIVERGENT`, or `INSUFFICIENT` when fewer than two sources answered decisively),
the claims, and the findings. A finding is `suspected` when first seen and
`confirmed` once re-observed past the detector's `staleness_window_s` (so
legitimate propagation lag isn't mistaken for tampering).

Long-running? Keep a detector and route new findings to your alert sink — it
deduplicates, so a persisting divergence fires your callback once:

```python
from sm_divergence import DivergenceDetector

detector = DivergenceDetector(
    ["https://registry-a.example", "https://registry-b.example"],
    on_finding=lambda f: alert(f.kind, f.agent_id, f.detail),
    staleness_window_s=300,
)
await detector.check(watch_ids=my_agent_ids)   # call each poll cycle
```

### The Corroboration Record

Every sweep can be sealed into a signed, content-addressed **Corroboration
Record** (draft §9) — the auditable proof that the checks ran, emitted for every
subject *whatever the verdict* (the `AGREE` record is the positive attestation,
not just the `DIVERGENT` ones):

```python
from sm_divergence import sign_sweep, verify_corroboration_record

records = sign_sweep(results, sweeper_private_key=my_ed25519_key)  # needs [attestation]
# record_id = SHA-256(JCS(body)); signed by the sweeper's did:key
assert all(verify_corroboration_record(r) for r in records)        # verifies offline
```

## CLI

```bash
python -m sm_divergence check \
    --registry https://registry-a.example \
    --registry https://registry-b.example \
    --watch agent-1 --watch agent-2
```

Exit **0** when the sources agree, **2** when any divergence is found (so a cron
or CI step fails loudly), **1** on a usage error. Add `--json` for machine
output, `--attestation` to also compare verified DIDs, `--nanda-index URL`
beside `--registry URL` to corroborate a NANDA Index.

## What it compares

Every finding is `omission` (present on one source, positively absent on another)
or the name of a view field whose values disagree. The detail is uniform:
`{"field": <name>, "values": {source: value}}` (or `{"present_on", "missing_from"}`
for omission), so a consumer parses findings the same way at every layer.

| Kind | Meaning |
| --- | --- |
| `omission` | One source serves the id; another **positively** reports it absent (404 / soft-404). An *unreachable* source is excluded — a timeout is not a claim. |
| `endpoint` | Discovery sources disagree on an agent's endpoint. |
| `did` | Discovery sources with a **verified** attestation disagree on the key. One valid record + one forged one is *not* a disagreement — only proven DIDs count. |
| `key` | Identity sources (DID methods) disagree on the agent's verification key. |
| `source_equivocation` | One source, observed from several **vantages**, disagrees with *itself* on a field — equivocation by that source, distinct from disagreement between sources. |
| `agent_equivocation` | The agent's *own key* signed two different self-descriptions at the same `seq` — key compromise or a lying agent (the one finding about the agent, not a source). |
| `stale_description` | A source serves a self-description behind the highest `seq` (replay / lag). |

## Architecture — a kernel and its layers

The primitive factors into a source-agnostic **kernel** and a **layer** per thing
a middleman can be asked. Each layer supplies its own view and thin resolvers;
the kernel is untouched.

```
sm-resolver  (dependency)  the source-agnostic kernel — Resolver[T], the View
                           contract, Claim, diff_claims, Corroborator, SweepResult
sm_divergence/
  discovery/   registry-integrity layer — RecordView + HttpByIdResolver (NEST)
               + NandaIndexV2Resolver
  identity/    key-consistency layer — DidView + DidKeyResolver / DidWebResolver
               / UniversalResolverResolver + signed self-description
  record.py    the signed Corroboration Record (draft §9)
```

The kernel now lives in its own package,
[`sm-resolver`](https://github.com/Sharathvc23/sm-resolver) — `sm-divergence` is
the reference set of layers built on it. Everything below is re-exported from the
top level, so `from sm_divergence import Corroborator, Finding, …` is unchanged.

**Sources of different formats mix in one run.** A `Resolver` hides one source's
wire format and normalizes its answer to the same view the diff understands:

```python
from sm_divergence import DivergenceDetector, HttpByIdResolver, NandaIndexV2Resolver

await DivergenceDetector([
    HttpByIdResolver("https://nest.example"),        # GET /api/agents/{id}
    NandaIndexV2Resolver("https://index.example"),   # two-hop resolve → record
]).check(["agent-1"])
```

**Identity layer** — catches a `did:web` (or a Universal Resolver) serving a
different verification key than the agent's self-certifying `did:key` root, a
`key` divergence (the identity analogue of a tampered endpoint):

```python
from sm_divergence import Corroborator, DidKeyResolver, DidWebResolver

await Corroborator([
    DidKeyResolver(did_for=lambda a: agent_did_key[a]),   # offline root of truth
    DidWebResolver(did_for=lambda a: agent_did_web[a]),   # fetched, may be hijacked
]).check(agent_ids)
```

**A new format or layer is a thin adapter** — a view with a `comparable()` and a
`Resolver` that returns it; the generic `Corroborator` + `diff_views` do the rest:

```python
from collections.abc import Mapping
from dataclasses import dataclass
from sm_divergence import Corroborator

@dataclass(frozen=True)
class MyView:
    field: str | None = None
    def comparable(self) -> Mapping[str, str | None]:
        return {"field": self.field}

class MyResolver:
    label = "src-a"
    async def resolve(self, agent_id): ...   # -> (Status, MyView | None)

await Corroborator([MyResolver(), ...]).check(agent_ids)
```

**Signed correspondence** — the same agent is a bare id on one registry, a URN
locator on an Index, a `did:web` on a domain, and corroboration can't infer that
these are the same agent. Instead of trusting a caller-supplied mapping, let the
agent *sign* its own aliases + endpoints; verify offline and drive the resolvers
from the verified names, so a source that disagrees is contradicting the agent's
own signature:

```python
from sm_divergence import (
    build_self_description, HttpDescriptionResolver, corroborate_descriptions,
    signed_alias_for, DidWebResolver, AliasClosureResolver, binds_by_key,
)

# the agent signs (bumping seq on every re-issue), with its did:key's private key.
# The bundle is the draft §8 shape: {version, subject, seq, aliases, endpoints, signature}.
bundle = build_self_description(
    aliases={"web": "did:web:acme.org", "nanda": "urn:ai:…:acme"},
    endpoints=["https://acme.example/agents/acme"],
    private_key=agent_ed25519_private_bytes, seq=5,
)

# a consumer fetches the description from EVERY source and reconciles it —
# omission / replay / agent-equivocation on the description itself become findings:
recs = await corroborate_descriptions(
    [HttpDescriptionResolver(s) for s in source_urls], ["acme"],
)
canonical = recs["acme"].canonical                       # None if the agent equivocates
sds = {"acme": canonical} if canonical else {}

# drive resolvers from the PROVEN aliases, with closure so a claimed alias that
# doesn't bind back to the did:key contributes no claim (never a false divergence):
web = DidWebResolver(did_for=signed_alias_for(sds, "web"))
web = AliasClosureResolver(web, lambda a: sds[a].subject if a in sds else None, binds_by_key)
```

> The kernel lives in [`sm-resolver`](https://github.com/Sharathvc23/sm-resolver);
> `sm-divergence` is the reference layers built on it. The top-level public API is
> unchanged.

For verified-DID comparison over signed records shaped
`{"record": {..., "did": "did:key:z…", "endpoint": …}, "sig": "<b64 ed25519 over JCS(record)>"}`,
use the built-in adapter (needs the `attestation` extra):

```python
from sm_divergence import DivergenceDetector, signed_record_adapter
DivergenceDetector(registries, adapter=signed_record_adapter())
```

## Related packages

| Package | Role |
| --- | --- |
| [`sm-bridge`](https://github.com/Sharathvc23/sm-bridge) | NANDA-compatible registry endpoints + Quilt-style deltas — *produces* the multi-source surface this corroborates across. |
| [`sm-chapter`](https://github.com/Sharathvc23/sm-chapter) | Minimal registry/discovery server — a natural *consumer* that runs a divergence check each cycle. |
| [`sm-conformance`](https://github.com/Sharathvc23/sm-conformance) | The shared Ed25519 / JCS signing convention this library's optional DID check verifies. |

## Develop

```bash
make ci-local   # uv: sync → ruff → format → mypy --strict → pytest
```

## License

[MIT](LICENSE)

---

*First published: 2026-07-04 | Last modified: 2026-08-28*

*Published by [Stellarminds.ai](https://stellarminds.ai) under the MIT licence.
Aligned with [Project NANDA](https://projectnanda.org) standards.*
