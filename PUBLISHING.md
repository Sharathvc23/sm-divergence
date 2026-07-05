# Publishing sm-divergence to PyPI

`sm-divergence` publishes via **PyPI Trusted Publishing** — no API tokens. You
tell PyPI once that this repo's `release.yml` workflow may publish; after that,
pushing a version tag builds and uploads automatically.

## Prerequisite — the sm-resolver dependency

`sm-divergence` depends on [`sm-resolver`](https://github.com/Sharathvc23/sm-resolver)
(the kernel). Today `pyproject.toml` pins it as a **git URL**:

```toml
"sm-resolver @ git+https://github.com/Sharathvc23/sm-resolver.git@main"
```

PyPI **rejects** packages with direct-reference (URL/git) dependencies, so before
the first release you MUST:

1. Publish `sm-resolver` to PyPI (see its `PUBLISHING.md`).
2. In `sm-divergence`'s `pyproject.toml`, replace the git URL with a normal
   version spec, e.g. `"sm-resolver>=0.1"`, and remove the
   `[tool.hatch.metadata] allow-direct-references = true` line.

(The git URL is fine for development and this repo's CI; it just can't ship to
PyPI.)

## One-time setup (≈5 minutes — this is the part only you can do)

1. Sign in to PyPI (the same account that publishes the rest of the `sm-*` family).
2. Go to **https://pypi.org/manage/account/publishing/** → "Add a pending
   publisher" (use *pending* — the first publish creates the project).
3. Fill the form with **exactly** these values:

   | Field | Value |
   |-------|-------|
   | PyPI Project Name | `sm-divergence` |
   | Owner | `Sharathvc23` |
   | Repository name | `sm-divergence` |
   | **Workflow name** | `release.yml`  ← just the filename |
   | Environment name | *(leave blank)* |

That's it. No secret is created or stored anywhere.

## Releasing (every time, after setup)

```bash
# bump `version` in pyproject.toml + update CHANGELOG, commit, then:
git tag v0.7.0
git push origin v0.7.0
```

The `release` workflow builds the sdist + wheel, runs `twine check`, and uploads
to PyPI over OIDC. Watch it under the repo's **Actions** tab.

## Notes

- The tag (`v0.7.0`) and `version` in `pyproject.toml` must match.
- Dry run anytime, no upload: `python -m build && python -m twine check dist/*`.
