.PHONY: ci-local
# One-command pre-push gate — the same steps CI runs, hard-failing on first red.
ci-local:
	uv sync --extra dev
	uv run ruff check .
	uv run ruff format --check .
	uv run mypy sm_divergence
	uv run pytest -v
	uv run python examples/registry_divergence.py
	uv run python examples/known_subject_sweep.py
	uv run python examples/identity_key_divergence.py
	uv run python examples/signed_self_description.py
	uv run python examples/corroboration_record.py
