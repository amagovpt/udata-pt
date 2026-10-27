# Backend - udata (dados.gov.pt)

## Stack
- Python 3.11-3.13, Flask, MongoDB (mongoengine), Celery + Redis, Elasticsearch
- Package manager: **uv** (never use pip directly)
- Based on the udata open data platform

## Commands

```bash
# Install dependencies
uv sync --extra dev --extra test

# Run dev server (port 7000)
inv serve

# Run Celery worker / scheduler
inv work
inv beat

# Initialize DB
udata init

# Run migrations
udata db migrate

# Run tests (needs MongoDB on port 27018)
docker compose -f docker-compose.test.yml up -d
uv run pytest

# Run tests with coverage
uv run inv test --report --ci

# Lint & format
uv run ruff check --extend-select I --fix .
uv run ruff format .
```

## Code Style

- Follow PEP-8, PEP-257, Google Python Style Guide
- All code, comments, and docstrings in **English**
- Formatting/linting handled by **Ruff** (ruff check + ruff format)
- Type hints: use modern annotations (`dict[str, str]`, `list[int]`, `Self`)
- Naming: `snake_case` functions/variables, `PascalCase` classes, `UPPER_CASE` constants

## Architecture

- **App factory**: `udata/app.py` -> `create_app()` + `standalone()`
- **Config**: `udata/settings.py` (Defaults, Debug, Testing classes)
- **Core modules** in `udata/core/` (dataset, organization, reuse, dataservices, etc.)
- Each module follows: `models.py`, `api.py`, `permissions.py`, `factories.py`, `tasks.py`, `signals.py`
- **Migrations** in `udata/migrations/` (date-prefixed scripts)
- **Tests** in `udata/tests/` and within each module's `tests/` dir

## Performance

- **Aggregated endpoints** — For pages that need data from multiple models, create a single endpoint returning everything in one response (e.g., `/api/1/site/home/`). Use manual dict serialization with helper functions (`_serialize_dataset()`, `_serialize_reuse()`) including only the fields the frontend needs, instead of full Flask-RestX marshalling.
- **Server-side caching** — Use `@cache.cached(timeout=N, key_prefix="...")` from Flask-Caching on aggregated/read-heavy endpoints (e.g., `timeout=300` for homepage data).
- **Query limiting** — Always limit querysets with `[:N]` slicing when only a fixed number of results is needed, instead of fetching all and truncating.

## Key Conventions

- Pre-commit hooks: ruff check, ruff format, trailing whitespace, end-of-file fixer
- Commit messages: follow [Conventional Commits](#branch--commit-conventions), readable, detailed, include `(fix #XXX)` to auto-close issues. **Never add `Co-Authored-By` or any AI attribution to commit messages.**
- Branches: follow [Conventional Branch](#branch--commit-conventions) (`<type>/<kebab-case-description>`).
- **Update `CHANGELOG.md` after every notable change** (mandatory once the implementation is done). Add the entry at the top under `## Unreleased`, in the existing style: a **bold one-line summary**, followed by indented sub-bullets explaining the *why/how*. Describe the behaviour that changed and the reasoning — that is the whole value of the entry.
  - **Do not reference the PR, and never write a `[#XXX]`/`[#NNN]` placeholder.** The PR number does not exist when the entry is written, and the merge commit already records it (`Merge pull request #180 from …`), so `git log --grep` finds it. Placeholders were the single largest source of promotion conflicts: the number got filled in on one branch only, so the same entry ended up with different text on `tst` and `ppr` and a line that should auto-merge conflicted instead. **Reference neither PRs nor Jira ticket ids.**
  - **Never edit an entry that has already been promoted** to another environment branch, for the same reason.
  - Conflicts in `## Unreleased` from two branches both inserting at the top are expected and safe: **keep both entries**, newest first. Never resolve one by deleting the other side's entry.
- Tests use pytest with MongoDB (port 27018 via docker-compose.test.yml)
- Coverage config in `coverage.rc` (branch coverage, excludes test dirs)

## Branch & Commit Conventions

All contributors must follow these conventions. References:
[Conventional Branch](https://conventionalbranch.org/) and [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).

### Branches — Conventional Branch

Format: `<type>/<description>`

- **Description** in `kebab-case`, lowercase, alphanumerics and hyphens only (no spaces, `_`, uppercase, or special chars).
- Optionally include the issue/ticket number: `feature/issue-123-public-search-ratelimit`.

| Prefix     | Use                                                       |
| ---------- | --------------------------------------------------------- |
| `main`     | Main production branch (no prefix).                       |
| `feature/` | New feature.                                              |
| `bugfix/`  | Bug fix.                                                  |
| `hotfix/`  | Urgent fix (typically against production).                |
| `release/` | Release preparation.                                      |
| `chore/`   | Tasks with no production-code impact (deps, config).      |

Examples: `feature/aggregated-home-endpoint`, `bugfix/csrf-session-overwrite`, `chore/bump-backend-submodule`, `hotfix/download-ratelimit`.

### Environment Promotion Flow

This backend repo (`github.com/amagovpt/udata-pt`) has long-lived environment branches `develop`, `tst`, `ppr`, `main`. Promote changes upwards through PRs, one environment at a time:

1. Branch **from `develop`** (using the Conventional Branch naming above).
2. When ready, open a PR back **into `develop`**; integrate and test there.
3. Then a PR **into `tst`**; test in tst.
4. Then a PR **into `ppr`**; test in ppr.
5. Then a PR **into `main`** (production).

> The PR base is always the **next environment up**, not always `main`. Apply this flow only when the change touches this repo. Check `gh auth status` first — the GitHub CLI is available on some team machines and not on others. When it is authenticated, open the PR with `gh pr create --repo amagovpt/udata-pt --base <base> --head <branch>` and follow CI with `gh pr checks`; otherwise open it via the compare URL `https://github.com/amagovpt/udata-pt/compare/<base>...<head>?expand=1`. See the monorepo `CLAUDE.md` for the cross-repo rule.

### Versioning & Releases

This repo is a fork of [udata](https://github.com/opendatateam/udata) and versions itself as `vX.Y.Z.N`:

- `X.Y.Z` — the upstream udata version the fork is built on. Today: **16.0.0**. Confirm it at every upstream sync, and **never by reading `pyproject.toml` or what `uv sync` prints**: that literal said `15.1.0` for eight months while the code was already on 16.0.0, because upstream computes its version from git tags and this fork froze a hand-written one instead. The three checks that do answer it — ancestry, the files a release added and removed, and the migrations already applied — are in [`docs/versioning.md`](docs/versioning.md#which-upstream-version-is-this-fork-on-and-why-pyprojecttoml-cannot-answer-it).
- `N` — the Portuguese revision. Incremented on every promotion to `main`, and **reset to `1` at each upstream sync** (once synced to 17.14.0, the next release is `17.14.0.1`). It counts the revisions sitting on *this* base, not Portuguese releases ever made: two thirds of what the fork changes are upstream files it modifies, and those are reconciled from scratch at each sync. Same reasoning as Debian revisions and RPM `Release` fields; the long version is in `docs/versioning.md`.

Four segments never collide with upstream, which only ever publishes three, and they sort correctly under PEP 440 (`16.0.0 < 16.0.0.1 < 16.0.1 < 16.1.0`). Do not use `16.0.0+pt.1` (the `+` is invalid as a Docker tag) nor `16.0.0-pt.1` (SemVer sorts a hyphen suffix *before* `16.0.0`).

Cutting a release:

1. The content reaches `main` through the normal promotion flow — never commit or push directly to an environment branch.
2. Put a `## 16.0.0.N (YYYY-MM-DD)` heading over that release's entries in `CHANGELOG.md`, and set the same number in `version` in `pyproject.toml`.
3. Run `./tag-version.sh 16.0.0.N --keep-changelog` from a working branch whose HEAD matches `origin/main`. It tags, pushes the tag and opens the GitHub release with the notes read from that changelog section, without rewriting the changelog. It refuses to tag when `pyproject.toml` declares a different version than the one being tagged — the two drifting apart is what put a stale number in the portal footer for months.
4. After the environment is deployed, confirm it is serving what you tagged: `../scripts/check_deployed_version.sh https://dados.gov.pt 16.0.0.N`. The version the API reports comes from the installed distribution metadata, so code deployed without the package being reinstalled keeps answering with the previous one.
5. One tag per promotion to `main` — the same cadence `dadosgov-fe` uses.

Never let upstream tags into the main tag namespace; they would mix with this fork's releases. Configure the remote once:

```bash
git remote add upstream https://github.com/opendatateam/udata.git
git config remote.upstream.tagOpt --no-tags
# when you do need to compare against upstream, keep its tags namespaced:
git fetch upstream '+refs/tags/*:refs/tags/upstream/*' --no-tags
```

### Commits — Conventional Commits 1.0.0

Format:

```
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

- **type** (required): `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
- **scope** (optional): affected area, e.g. `feat(dataset):`, `fix(api):`.
- **description**: imperative, lowercase, in English, no trailing period.
- **`feat`** → _MINOR_ bump; **`fix`** → _PATCH_ bump.
- **Breaking changes**: `!` after type/scope (e.g. `feat(api)!:`) and/or a `BREAKING CHANGE: <description>` footer.
- Reference issues in the footer or description: `(fix #XXX)`.

Examples:

```
feat(search): add user_or_ip rate-limit to public GET endpoints
fix(auth): mint CSRF server-side on authenticated POSTs (fix #42)
chore: bump backend submodule for public download rate-limit fix
refactor(home): add aggregated /api/1/site/home/ endpoint
```

## Important Paths

- `udata/app.py` - Flask app factory
- `udata/settings.py` - Configuration
- `udata/api/__init__.py` - API registration
- `udata/core/` - All domain modules
- `udata/harvest/` - Harvesting framework (CKAN, DCAT)
- `udata/migrations/` - Database migrations
- `manage.py` - CLI entry point
