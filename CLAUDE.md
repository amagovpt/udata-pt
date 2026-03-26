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
udata db upgrade

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
- Commit messages: readable, detailed, include `(fix #XXX)` to auto-close issues. **Never add `Co-Authored-By` or any AI attribution to commit messages.**
- Update CHANGELOG.md when making notable changes
- Tests use pytest with MongoDB (port 27018 via docker-compose.test.yml)
- Coverage config in `coverage.rc` (branch coverage, excludes test dirs)

## Important Paths

- `udata/app.py` - Flask app factory
- `udata/settings.py` - Configuration
- `udata/api/__init__.py` - API registration
- `udata/core/` - All domain modules
- `udata/harvest/` - Harvesting framework (CKAN, DCAT)
- `udata/migrations/` - Database migrations
- `manage.py` - CLI entry point
