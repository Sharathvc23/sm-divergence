# Internet-Draft

`draft-chandra-agent-registry-corroboration` — *Multi-Source Corroboration for AI
Agent Discovery*.

## Revisions

| | Status |
| --- | --- |
| `-00` | Submitted 2026-07-04. Superseded. |
| `-01` | Submitted 2026-08-27. **Current published revision.** Expires 2027-02-28. |
| `-02` | Prepared (dated 2026-10-30). **Not submitted.** Ready for `idnits` and submission. |

- Datatracker: <https://datatracker.ietf.org/doc/draft-chandra-agent-registry-corroboration/>
- HTML: <https://datatracker.ietf.org/doc/html/draft-chandra-agent-registry-corroboration>
- `-01` text: <https://www.ietf.org/archive/id/draft-chandra-agent-registry-corroboration-01.txt>

**The files here are the bytes that were submitted.** `-01` was verified
byte-identical to what the IETF serves; do not rebuild them in place. A rebuild
changes the date line and therefore the expiry, and the published revision is
immutable.

## What -02 adds

**Alignment with registry-assisted resolution of known subjects** (the
DAWN-aligned profile, `draft-raskar-agentic-web-federated-resolution-02`):

- **Section 2** defines *Binding* (a renewable lease with a `sequence` per
  authority scope) beside the agent's own self-description `seq`.
- **Section 4.1** seeds `expired` and `revoked` outcomes.
- **Section 5** lets a view carry a lease position; neither it nor the
  authority issuer is ever compared.
- **Section 6.4 (new)** Supersession: a claim below the current sequence in its
  scope is `stale_binding`, attributed and withheld from the field diff. Lag is
  attributed, not accused. Implemented in `sm-resolver` 0.7.0.
- **Section 10** claim entries carry `binding`; record version
  `corroboration/0.4`. Implemented in `sm-divergence` 0.12.0.
- **Section 11** the discovery view gains `digest`; a known-subject resolver
  (`POST /resolve`) is the first discovery resolver; the two-hop index resolver
  is legacy.
- **Section 12 (new)** states the relationship: resolution is one source's
  answer, corroboration the comparison; no forwarding; bounded fan-out and
  exact lookup; authority evidence is provenance, never verdict; the direct DNS
  path as a source; Answer Scope beside target scope.
- **Section 15** adds *Fan-out and enumeration* and *Authority laundering*.
- Related Work cites the DAWN charter, terminology and requirements drafts.

Sections 12-15 of the earlier `-02` text are renumbered 13-16.

**Earlier -02 changes** (claim outcomes, `alg`):

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

The `.mkd` is authoritative. The 2026-10-30 `.xml` was produced by porting the
`.mkd` edits into the previous kramdown-rfc output by hand (kramdown-rfc was
unavailable in the build environment) and rebuilt to `.txt` with xml2rfc; a
`kramdown-rfc` rebuild from the `.mkd` before submission is advisable and
should produce the same document. Rebuild with:

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
