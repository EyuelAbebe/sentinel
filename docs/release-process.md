# Release Process

Sentinel uses a two-stage release process. A **release candidate (RC)** is created first and tested in isolation. A separate **promote** step turns that RC into a production release with no code changes between the two.

---

## Overview

```
feature branch ──PR──▶ main
                          │
              ┌───────────┘
              │ Actions → Create Release Candidate
              │ (manual workflow_dispatch)
              │
              ▼
        v0.x.y-rc.1  ◀── runs full test suite,
                          bumps version, commits,
                          tags and pushes
              │
              │ Actions → Promote to Release
              │ (manual workflow_dispatch)
              │
              ▼
          v0.x.y  ──▶  GitHub Release + PyPI
```

Production releases are always triggered manually. No code is modified between RC and release — `promote` builds from the exact commit the RC tag points to.

---

## Step 1 — Merge your PR

Work on a feature or fix branch, open a PR, and merge it into `main`. CI runs automatically on every branch push and every PR.

---

## Step 2 — Create a release candidate

Go to **GitHub → Actions → Create Release Candidate → Run workflow**.

| Input | Options | When to use |
|---|---|---|
| `bump` | `patch` | Bug fixes only |
| `bump` | `minor` | New features, backwards-compatible |
| `bump` | `major` | Breaking changes |

**What happens:**

1. Runs `ruff`, `mypy`, and `pytest` against `main`
2. If all pass: runs `poetry version {bump}` to increment `pyproject.toml`
3. Commits the version bump and pushes to `main`
4. Creates and pushes the tag `v{version}-rc.1` (or `-rc.N+1` if one already exists)

If any step fails, the workflow aborts — no version bump is committed, no tag is created.

---

## Step 3 — Update CHANGELOG.md

Before promoting, add an entry to `CHANGELOG.md`:

```markdown
## [0.2.0] — YYYY-MM-DD

### Added
- Short description of new behaviour

### Fixed
- Short description of bug fix
```

The promote workflow extracts this section as the GitHub Release description.

---

## Step 4 — Promote to a production release

Go to **GitHub → Actions → Promote to Release → Run workflow**.

| Input | Example |
|---|---|
| `rc_tag` | `v0.2.0-rc.1` |

**What happens:**

1. Checks out the exact commit the RC tag points to (no `main` drift)
2. Runs `pytest` one final time against that commit
3. Verifies `pyproject.toml` version matches the tag
4. Creates and pushes the final tag `v{version}` on the same commit
5. Builds wheel + sdist with `poetry build`
6. Creates a GitHub Release with CHANGELOG notes and the built artifacts attached
7. Publishes to PyPI (if `PYPI_TOKEN` secret is configured — see below)

---

## PyPI setup

To enable PyPI publishing:

1. Create an API token at [pypi.org/manage/account/token](https://pypi.org/manage/account/token/)
2. In GitHub: **Settings → Secrets and variables → Actions → New repository secret**
   - Name: `PYPI_TOKEN`
   - Value: the token from step 1

The `promote` workflow skips the PyPI step entirely if the secret is absent.

---

## Semantic versioning

| Change | Bump |
|---|---|
| Bug fix, no behaviour change | `patch` → 0.1.0 → 0.1.1 |
| New feature, backwards-compatible | `minor` → 0.1.0 → 0.2.0 |
| Breaking change to CLI, API, or data format | `major` → 0.1.0 → 1.0.0 |

Until v1.0.0, `minor` bumps may include breaking changes — document them clearly in `CHANGELOG.md`.

---

## Re-running a failed RC

If the RC test run fails partway through and a bad tag is pushed, delete it before retrying:

```bash
git tag -d v0.2.0-rc.1
git push origin :refs/tags/v0.2.0-rc.1
```

Then fix the issue on `main`, and trigger the workflow again. It will create `v0.2.0-rc.2`.

---

## Hotfix releases

For an urgent fix on a released version:

```bash
git checkout -b fix/critical-bug v0.x.y   # branch from the release tag
# ... make the minimal fix ...
git push origin fix/critical-bug
# open a PR to main; merge it
# then trigger Create RC with bump=patch
```

The resulting `v0.x.(y+1)-rc.1` can be promoted immediately.
