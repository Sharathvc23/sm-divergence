# Internet-Draft

`draft-chandra-agent-registry-corroboration` — *Multi-Source Corroboration for AI
Agent Discovery*.

## Revisions

| | Status |
| --- | --- |
| `-00` | Submitted 2026-07-04. Superseded. |
| `-01` | Submitted 2026-08-27. **Current published revision.** Expires 2027-02-28. |
| `-02` | Prepared. **Not submitted.** |

- Datatracker: <https://datatracker.ietf.org/doc/draft-chandra-agent-registry-corroboration/>
- HTML: <https://datatracker.ietf.org/doc/html/draft-chandra-agent-registry-corroboration>
- `-01` text: <https://www.ietf.org/archive/id/draft-chandra-agent-registry-corroboration-01.txt>

**The files here are the bytes that were submitted.** `-01` was verified
byte-identical to what the IETF serves; do not rebuild them in place. A rebuild
changes the date line and therefore the expiry, and the published revision is
immutable.

## What -02 adds

Two gaps a review of `-01` identified, both now implemented and released before
the text was written rather than after:

- **Section 4.1** makes claim outcomes a seeded vocabulary. `-01` left the member
  free-form, so implementations would have minted incomparable strings for the
  same condition. Implemented in `sm-resolver` 0.5.0.
- **Section 10** adds `alg` and requires a verifier to derive the algorithm from
  the key type the `sweeper` `did:key` encodes rather than trusting the record.
  `-01` named no algorithm at all. Record version becomes `corroboration/0.3`.
  Implemented in `sm-divergence` 0.10.0.

It also carries the ASCII cleanup prepared after `-01` was submitted, so `-02` is
ASCII-only and does not draw the non-ASCII line-length reports `-01` did.

The `.mkd` is authoritative. Rebuild with:

```
kramdown-rfc draft-chandra-agent-registry-corroboration-01.mkd \
  > draft-chandra-agent-registry-corroboration-01.xml
xml2rfc draft-chandra-agent-registry-corroboration-01.xml \
  -o draft-chandra-agent-registry-corroboration-01.txt
```

## What changed in -01

The Answer Scope (Section 9) and everything that follows from it. See the
**Changes from -00** appendix in the draft itself for the full list.

Sections 9–14 of `-00` are renumbered to 10–15, because the Answer Scope is
inserted beside the Self-Description rather than appended.
