# Internet-Draft

`draft-chandra-agent-registry-corroboration` — *Multi-Source Corroboration for AI
Agent Discovery*.

## Revisions

| | Status |
| --- | --- |
| `-00` | Submitted 2026-07-04. Superseded. Expires 2027-01-05. |
| `-01` | **Submitted 2026-08-27. Current.** Expires 2027-02-28. |

- Datatracker: <https://datatracker.ietf.org/doc/draft-chandra-agent-registry-corroboration/>
- HTML: <https://datatracker.ietf.org/doc/html/draft-chandra-agent-registry-corroboration>
- `-01` text: <https://www.ietf.org/archive/id/draft-chandra-agent-registry-corroboration-01.txt>

**The files here are the bytes that were submitted.** `-01` was verified
byte-identical to what the IETF serves; do not rebuild them in place. A rebuild
changes the date line and therefore the expiry, and the published revision is
immutable.

## Pending for -02

An ASCII cleanup was prepared after `-01` was submitted and is **not** part of
the published revision: all 80 em dashes converted to commas, colons and
parentheses, which removes the non-ASCII warnings idnits reports and follows the
IETF preference for those forms. It is in commit `dcf788b` and should be the
starting point for `-02` rather than being re-done.

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
