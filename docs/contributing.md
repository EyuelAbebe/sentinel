# Contributing

## Development setup

**Requirements:** macOS 14+, Python 3.12+, [Poetry](https://python-poetry.org), [pipx](https://pipx.pypa.io) (optional)

```bash
git clone https://github.com/EyuelAbebe/sentinel.git
cd sentinel
poetry install          # installs runtime + TUI + dev tools
poetry run sentinel doctor
```

## Branching model

```
main ← always in a releasable state
 ├── feature/<name>    one PR per feature
 └── fix/<name>        one PR per bug fix
```

All work happens on a branch. Direct commits to `main` are not permitted. A PR requires CI to pass before it can be merged.

## Daily workflow

```bash
# start a new branch
git checkout -b feature/my-thing

# ... make changes ...

make fmt           # auto-fix formatting + lint
make lint          # ruff check (read-only)
make typecheck     # mypy strict
make test          # pytest

# push and open a PR
git push origin feature/my-thing
```

## Make targets

| Command | What it does |
|---|---|
| `make install` | `poetry install` |
| `make test` | `pytest` |
| `make lint` | `ruff check + format --check` |
| `make fmt` | `ruff check --fix + format` |
| `make typecheck` | `mypy` |

## Architecture rules

These rules are enforced by the architecture and must not be broken:

| Layer | May import |
|---|---|
| `domain/` | stdlib only |
| `application/` | `domain/` + collector Protocols |
| `collectors/` | `domain/` + psutil |
| `cli/` | `application/` + `domain/` + typer + rich |
| `tui/` | `application/` + `domain/` + textual |
| `storage/` | `domain/` + sqlalchemy + alembic |

`cli/` must never import `tui/`, and vice versa. All scanning logic lives in `application/` — never in `cli/` or `tui/`.

## Adding a new signal to the FindingEngine

1. Add the signal in `src/sentinel/application/finding_engine.py`
2. Write a unit test in `tests/unit/test_finding_engine.py` — one for the happy path and one proving it does **not** fire on the benign case
3. Update the signals table in `CLAUDE.md`

## Code conventions

- `datetime.now(UTC)` — never `datetime.utcnow()` (deprecated in 3.13)
- Collectors must catch `psutil.AccessDenied` and `psutil.NoSuchProcess` and return an empty list
- Never log sensitive values (cookies, auth headers, passwords) at any level
- Findings always have at least one `FindingReason` — never surface a finding without explaining why
- JSON output (`sentinel scan --json`) must produce clean JSON; test with `sentinel scan --json 2>/dev/null`

Full details: [CLAUDE.md](../CLAUDE.md)

## Tests

```bash
make test                        # run everything
poetry run pytest tests/unit/    # unit tests only (no real sockets)
poetry run pytest tests/integration/  # integration tests (auto-skip under macOS SIP)
```

Unit tests use only fixtures — no real processes or sockets.  
Integration tests bind real sockets and skip automatically when `psutil.net_connections()` raises `AccessDenied`.

## Project layout

```
src/sentinel/
  domain/         Pydantic models and enums — no I/O
  application/    Scan orchestration, correlation, finding engine
  collectors/     psutil-based data collection
  adapters/       Optional: osquery, YARA-X (later phases)
  cli/            Typer commands, Rich/JSON renderers
  tui/            Textual interactive TUI
  storage/        SQLite + Alembic (Phase 4+)

tests/
  unit/           Fast, fixture-driven
  integration/    Binds real sockets — skips under macOS SIP
```

## Architecture and design decisions

- [Architecture overview](architecture.md)
- [ADR-0001 — Local first](decisions/ADR-0001-local-first.md)
- [ADR-0002 — One engine, many interfaces](decisions/ADR-0002-one-engine-many-interfaces.md)
- [ADR-0003 — Event model](decisions/ADR-0003-event-model.md)
