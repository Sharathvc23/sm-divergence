"""SubjectMap — the names one subject goes by in each source.

A sweep asks every source about the same canonical watch id, but no two sources
file an agent under the same name: a zone knows it by FQDN, a log by an entry
id, a catalog by an identifier, a registry by its own key. Each resolver takes a
callable that maps the watch id to its source's name; ``SubjectMap`` holds those
names in one place and hands out the callables.

    subjects = SubjectMap({
        "support-agent": {
            "fqdn": "agent.example.com",
            "catalog": "urn:air:example.com:support",
            "log": "3f0c1a52-6b0e-4d57-9a44-2f6f0d1e7c11",
        },
    })
    DnsZoneResolver(owner_for=subjects.name("fqdn"))
    CatalogResolver("https://example.com", identifier_for=subjects.name("catalog"))
    await Corroborator([...]).check(subjects.ids())

**A missing name is not a claim.** Asking for a name the map does not hold
raises ``KeyError``; every resolver that takes such a callable reports that as
``error`` and sends no request. A subject that one source cannot be asked about
is therefore excluded from that source, never reported as absent from it — an
identity-correspondence gap must not surface as an omission finding.

The kinds are free-form strings; the map does not interpret them.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping


class SubjectMap:
    """Per-source names for the subjects under watch.

    ``subjects`` maps each canonical watch id to its names by kind. ``default``
    lists kinds for which a subject with no explicit name goes by its watch id
    itself (a sweep keyed by FQDN would pass ``default=("fqdn",)``).
    """

    def __init__(self, subjects: Mapping[str, Mapping[str, str]], *, default: tuple[str, ...] = ()) -> None:
        self._subjects = {subject: dict(names) for subject, names in subjects.items()}
        self._default = frozenset(default)
        for subject, names in self._subjects.items():
            for kind, value in names.items():
                if not isinstance(value, str) or not value:
                    raise ValueError(f"{subject!r}: the {kind!r} name is not a non-empty string")

    def ids(self) -> list[str]:
        """The canonical watch ids, in the order given."""
        return list(self._subjects)

    def kinds(self, subject: str) -> list[str]:
        """The kinds of name held for one subject."""
        return sorted(self._subjects[subject])

    def name(self, kind: str) -> Callable[[str], str]:
        """A callable mapping a watch id to its name of this kind.

        The callable raises ``KeyError`` for a subject that is not in the map or
        has no name of the kind (and the kind is not a default one).
        """

        def lookup(subject: str) -> str:
            names = self._subjects[subject]
            if kind in names:
                return names[kind]
            if kind in self._default:
                return subject
            raise KeyError(f"{subject!r} has no {kind!r} name")

        return lookup
