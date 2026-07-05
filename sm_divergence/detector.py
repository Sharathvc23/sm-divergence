"""The discovery-layer product: a ``Corroborator`` specialized to registries.

``DivergenceDetector`` is a thin convenience over the core ``Corroborator`` — it
accepts bare registry URLs (wrapping them in ``HttpByIdResolver``) alongside
``Resolver`` instances of any format, so ``check_once(["https://a", "https://b"])``
keeps working while heterogeneous resolvers mix freely. The generic orchestration
lives in ``sm-resolver`` (the kernel); this file only adds the discovery defaults.
"""

from __future__ import annotations

from collections.abc import Iterable

from sm_resolver import Corroborator, OnFinding, Resolver, SweepResult

from .discovery import DEFAULT_PATH, HttpByIdResolver, RecordAdapter, RecordView, default_adapter

__all__ = ["DivergenceDetector", "OnFinding", "check_once"]


class DivergenceDetector(Corroborator[RecordView]):
    """Cross-registry divergence detector.

    Point it at two or more registries — each a base URL (wrapped in an
    ``HttpByIdResolver`` with the shared ``adapter``/``path``) or a ``Resolver``
    instance for a registry of a different format (e.g. ``NandaIndexV2Resolver``).
    Registries of different formats mix freely; each normalizes to a
    ``RecordView`` so the diff treats them uniformly. Fewer than two → no-op.
    """

    def __init__(
        self,
        registries: Iterable[str | Resolver[RecordView]],
        *,
        adapter: RecordAdapter = default_adapter,
        path: str = DEFAULT_PATH,
        on_finding: OnFinding | None = None,
        timeout: float = 10.0,
        staleness_window_s: float = 0.0,
    ) -> None:
        resolvers: list[Resolver[RecordView]] = [
            HttpByIdResolver(r, adapter=adapter, path=path, timeout=timeout) if isinstance(r, str) else r
            for r in registries
        ]
        super().__init__(resolvers, on_finding=on_finding, staleness_window_s=staleness_window_s)

    @property
    def registries(self) -> list[str]:
        """The registry labels being compared (back-compat + introspection)."""
        return self.labels


async def check_once(
    registries: Iterable[str | Resolver[RecordView]],
    watch_ids: Iterable[str],
    *,
    adapter: RecordAdapter = default_adapter,
    path: str = DEFAULT_PATH,
    timeout: float = 10.0,
) -> list[SweepResult[RecordView]]:
    """One-shot convenience: build a detector and run a single check, returning
    one ``SweepResult`` per watched id (verdict + claims + findings)."""
    return await DivergenceDetector(registries, adapter=adapter, path=path, timeout=timeout).check(watch_ids)
