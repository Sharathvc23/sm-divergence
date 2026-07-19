# Real run transcript — `live_nanda_index_v2_sweep.py`

Captured 2026-07-19 against a local testbed (`~/nanda-testbed`, per
`TESTBED_STATE.md`): NANDA Index v2 (`localhost:3001`), nanda-registry
(`localhost:3002`), host39 (`localhost:3010`). Every response below is a real
service response, not fabricated or hand-edited.

## Setup — seed one agent identity across two independent registries

```bash
# nanda-registry: register an account, create the agent
curl -s -X POST http://localhost:3002/auth/register -H 'content-type: application/json' \
  -d '{"email":"divergence-demo@example.com","password":"demoPass123!"}'
# -> {"token": "<jwt>"}

curl -s -X POST http://localhost:3002/agents -H 'content-type: application/json' \
  -H "Authorization: Bearer <jwt>" \
  -d '{"agent_id":"divergence-demo","display_name":"Divergence Demo Agent","url":"https://real.example/agent"}'
# -> HTTP 201 {"identifier":"divergence-demo", ..., "url":"https://real.example/agent", ...}

# host39: register a domain-identity account, create an independent card for
# the SAME logical agent (same watch id "divergence-demo"), same real URL
curl -s -X POST http://localhost:3010/auth/register -H 'content-type: application/json' \
  -d '{"email":"divergence-demo@host39.example","password":"demoPass123!","handle":"divergence-demo","identity_type":"domain","domain":"divergence-demo.test"}'
# -> {"token": "<jwt>"}

curl -s -X POST http://localhost:3010/cards -H 'content-type: application/json' \
  -H "Authorization: Bearer <jwt>" \
  -d '{"slug":"divergence-demo","display_name":"Divergence Demo Agent","runtime_url":"https://real.example/agent"}'
# -> HTTP 201 {"id":"2d0ce8b5-a29e-46aa-b382-c40009e49097","slug":"divergence-demo", ...}
```

Note: `nanda-corp`'s existing `registry_url` in the Index already points at
`nanda-registry` (`http://localhost:3002`), so nothing needed registering on
the Index side — the pre-seeded `acme-corp` org (from `TESTBED_STATE.md`'s own
proven walk) already resolves `urn:ai:domain:acme-corp.test:agent:<id>` to it.

## Baseline sweep — all three agree

```
$ python examples/live_nanda_index_v2_sweep.py
registries: ['nanda-index-v2 (via resolve)', 'nanda-registry (direct)', 'host39 (independent card)']

divergence-demo: AGREE
  claim  [nanda-index-v2 (via resolve)] status=present view=RecordView(endpoint='https://real.example/agent', did=None)
  claim  [nanda-registry (direct)] status=present view=RecordView(endpoint='https://real.example/agent', did=None)
  claim  [host39 (independent card)] status=present view=RecordView(endpoint='https://real.example/agent', did=None)
```

## Tamper — edit ONLY the host39 copy (bypassing both the Index and the registry)

```bash
curl -s -X PUT http://localhost:3010/cards/2d0ce8b5-a29e-46aa-b382-c40009e49097 \
  -H 'content-type: application/json' -H "Authorization: Bearer <jwt>" \
  -d '{"runtime_url":"https://attacker.example/hijacked"}'
```

Aside: `PUT`/`DELETE /cards/:slug` on this host39 build has a real bug —
it passes the slug straight through as the DB row's UUID param instead of
resolving by slug first (`PostgresError: invalid input syntax for type uuid:
"divergence-demo"`). Worked around by using the card's actual UUID (from the
create response) instead of its slug. Out of scope to fix here — read-only
upstream clone — but worth knowing if this example stops working after a
host39 update.

## Re-sweep — real DIVERGENT

```
$ python examples/live_nanda_index_v2_sweep.py
registries: ['nanda-index-v2 (via resolve)', 'nanda-registry (direct)', 'host39 (independent card)']

divergence-demo: DIVERGENT
  claim  [nanda-index-v2 (via resolve)] status=present view=RecordView(endpoint='https://real.example/agent', did=None)
  claim  [nanda-registry (direct)] status=present view=RecordView(endpoint='https://real.example/agent', did=None)
  claim  [host39 (independent card)] status=present view=RecordView(endpoint='https://attacker.example/hijacked', did=None)
  finding [endpoint/suspected] {'field': 'endpoint', 'values': {'host39 (independent card)': 'https://attacker.example/hijacked', 'nanda-index-v2 (via resolve)': 'https://real.example/agent', 'nanda-registry (direct)': 'https://real.example/agent'}}
```

The Index's own two-hop resolve and the registry it points at agree with each
other by construction (same backend) — the divergence is caught specifically
against the third, genuinely independent source, exactly the threat model
`sm-divergence` targets: a registry serving a different answer than what the
Index (and its declared registry) would lead you to expect.

## Healed — restored host39's copy, re-swept back to AGREE

```bash
curl -s -X PUT http://localhost:3010/cards/2d0ce8b5-a29e-46aa-b382-c40009e49097 \
  -H 'content-type: application/json' -H "Authorization: Bearer <jwt>" \
  -d '{"runtime_url":"https://real.example/agent"}'
```

```
$ python examples/live_nanda_index_v2_sweep.py
divergence-demo: AGREE
  claim  [nanda-index-v2 (via resolve)] status=present view=RecordView(endpoint='https://real.example/agent', did=None)
  claim  [nanda-registry (direct)] status=present view=RecordView(endpoint='https://real.example/agent', did=None)
  claim  [host39 (independent card)] status=present view=RecordView(endpoint='https://real.example/agent', did=None)
```

## A real bug this exercise also caught, upstream of the sweep itself

Running the earlier, single-file version of this script via
`python examples/live_nanda_index_v2_sweep.py` (i.e. as a script, not `python
-c` from the repo root) silently used a stale, pip-installed `sm-divergence`
0.8.0 from site-packages instead of this local checkout's fix — because
`python <script>` puts the script's own directory on `sys.path[0]`, not the
repo root, so the local package was shadowed. `pip install -e . --no-deps`
fixes this for local development; worth keeping in mind for anyone else
running these examples against a locally-modified checkout.
