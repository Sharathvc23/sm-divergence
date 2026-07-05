# Contributing to sm-divergence

Contributions are accepted under the Developer Certificate of Origin (DCO)
sign-off model. Add `Signed-off-by: Your Name <you@example.com>` to every commit
(`git commit -s`).

## Change process

1. Spec-affecting changes open a PR that updates the **spec (`SPEC.md`), the tests,
   and the code together**. Drift between these is a defect — the `tests/` suite is
   the authoritative behavioural specification of the diff.
2. The gate is `make ci-local` (uv: `ruff` → `ruff format` → `mypy --strict` →
   `pytest`). CI runs the same on Python 3.11 and 3.12. Push only when it is green.
3. Every new guarantee needs a happy-path test; every classification and every
   divergence kind needs its own case. The negative cases — unreachable ≠ absent,
   one-verified-DID ≠ divergence, soft-404 = absent — are the point.

## House rules

- **A timeout is not a claim.** An unreachable or erroring source MUST be
  excluded from the diff, never counted as an omission. This is the axiom the whole
  library rests on; a change here needs an RFC-style PR to `SPEC.md` first.
- **Only proven values disagree.** An unverified value (e.g. an unverified DID)
  never enters the diff. Do not weaken the verification path.
- **The diff stays pure and generic.** `diff_views` is deterministic, does no
  I/O, never raises, and never learns its layer. All I/O lives in the resolvers;
  a layer supplies a view (`comparable()`) and thin resolvers, nothing more.
- **No new crypto.** The optional DID check reuses the family convention
  (Ed25519 / `did:key` / JCS). Do not re-implement it elsewhere.
- **No expansion of the classification (SPEC §3), the view contract (SPEC §4), or
  the diff (SPEC §5) without an RFC-style PR to `SPEC.md` first.**
