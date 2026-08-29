# Sentinel — Claude Code Context

## What this project is

A local security and privacy monitoring tool for macOS. It watches running processes,
open ports, and network connections and surfaces anything unusual — without a cloud
backend, root access, or external dependencies for core operation.

CLI name: `sentinel` | Language: Python 3.12+ | Packaging: Poetry

---

## Essential commands

```bash
poetry install                  # install everything (runtime + dev)
poetry run sentinel             # launch TUI
poetry run sentinel scan        # one-shot quick scan
poetry run sentinel doctor      # check environment

make test                       # pytest
make lint                       # ruff check + format check
make fmt                        # auto-fix lint + format
make typecheck                  # mypy strict
make bump-patch                 # 0.x.y → 0.x.(y+1)
make bump-minor                 # 0.x.y → 0.(x+1).0
```

Tests run with `pytest-asyncio` in `auto` mode. All async tests just work.
Integration tests auto-skip if `psutil.net_connections()` is denied (macOS SIP).

---

## Project layout

```
src/sentinel/
  domain/         Pydantic models + enums — ZERO external deps
  application/    Orchestration services — NO UI dependency
  collectors/     psutil-based data collection
  adapters/       Optional: osquery, YARA-X, tracker data (not yet built)
  cli/            Typer commands + Rich / JSON renderers
  tui/            Textual interactive TUI
  storage/        SQLite + Alembic (Phase 4 — not yet built)
  config.py       SentinelConfig (pydantic-settings, env prefix SENTINEL_)
  log.py          Structured logging — always to stderr, never sensitive values

tests/
  unit/           Fast fixture-driven tests — no real processes or sockets
  integration/    Real socket/process tests — skip automatically if SIP blocks
```

---

## Architecture in brief

**One engine, many interfaces.** CLI, TUI, and (later) GUI all call the same
`QuickScanService`. Never add scanning logic to a CLI command or TUI screen.

Layer dependency rules (violating these breaks the architecture):
- `domain/` → nothing (pure Pydantic + stdlib)
- `application/` → `domain/` + collector Protocols only
- `collectors/` → `domain/` + psutil/macOS APIs only
- `cli/` → `application/` + `domain/` + rich + typer (NOT tui/)
- `tui/` → `application/` + `domain/` + textual (NOT cli/)
- `storage/` → `domain/` + sqlalchemy + alembic (NOT cli/ or tui/)

Full architecture details: `docs/architecture.md`

---

## Phase state

| Phase | What | Status |
|---|---|---|
| 0 | Bootstrap, CLI, config, logging, doctor | ✅ Done |
| 1 | Domain models, events, differ, event bus | ✅ Done |
| 2 | psutil collectors, correlation, finding engine, scan service | ✅ Done |
| 3 | Textual TUI (Overview / Apps / Network / Findings / Help) | ✅ Done |
| 4 | Live monitoring + SQLite persistence | Next |
| 5 | Identity / classification engine (domain → org → category) | Planned |
| 6 | Baselines and explainable findings | Planned |
| 7 | Deep scan + YARA-X | Planned |
| 8 | Browser extension (Chrome/Firefox) | Planned |
| 9 | GUI + local HTTP/WebSocket API | Planned |
| 10 | Zeek / Suricata adapters | Planned |
| 11 | macOS packaging, signing, hardening | Planned |

**Before starting any phase:** read the phase entry in
`local_security_monitor_build_spec.md` (repo root of the parent dir) and the
relevant ADRs in `docs/decisions/`.

---

## Key domain concepts

**ProcessIdentity** — a process snapshot. `instance_id` is a UUID5 from
`(pid, start_time)` — never use pid alone as a stable identity.

**SocketObservation** — a socket. Has `exposure: ExposureLevel` which is one of
`LOOPBACK`, `LOCAL_NETWORK`, or `ALL_INTERFACES`. This is the most important field
for the UI.

**Event** — a change (not a snapshot). The `SnapshotDiffer` produces events;
polling a stable state produces nothing.

**Finding** — always has `reasons: list[FindingReason]`. The UI always shows
reasons. Never surface a finding without at least one reason.

**ClassificationEvidence** — every classification has a `source` and
`source_version` so it remains traceable as datasets update.

---

## Signals in the FindingEngine

Current signals (all in `src/sentinel/application/finding_engine.py`):
- `all_interface_listener` — listening on `0.0.0.0` or `::`
- `local_network_listener` — listening on a specific non-loopback interface
- `suspicious_location` — executable path contains `/Downloads/`, `/tmp/`, `/var/tmp/`
- `executable_missing` — process running but executable no longer exists on disk

Severity derivation:
- `executable_missing` alone → HIGH
- `all_interface_listener` + `suspicious_location` → HIGH
- `all_interface_listener` alone → MEDIUM
- `suspicious_location` alone → MEDIUM
- Anything else → LOW

New signals must have a unit test in `tests/unit/test_finding_engine.py`.

---

## Critical conventions

1. **Graceful degradation everywhere.** Every collector and adapter catches
   `psutil.AccessDenied`, `psutil.NoSuchProcess`, and generic exceptions. A failed
   collector returns an empty list, not an exception that crashes the scan.

2. **Never log sensitive values.** Logging goes through `sentinel.log.get_logger()`.
   Do not log cookie values, auth headers, full URLs, passwords, or file contents.
   Even at DEBUG level.

3. **Findings explain themselves.** Never raise a finding severity from the UI layer.
   Severity is computed in `FindingEngine` from signals. UI reads `finding.severity`.

4. **JSON output has no ANSI.** When `--json` is passed, use `JsonRenderer`, which
   writes to `print()`. The Rich `Console` in `RichRenderer` writes to stdout, so
   always test that `sentinel scan --json 2>/dev/null` produces clean JSON.

5. **Pydantic models at boundaries.** Domain events and API contracts use Pydantic.
   Internal service state can use dataclasses (`CorrelatedProcess`, `ScanResult`).

6. **No subprocess parsing of lsof/netstat/ps.** psutil is the primary source for
   live data. Shell-out to system tools is a diagnostic fallback only.

7. **No new permissions without docs.** Any change that introduces a new OS
   permission must update `docs/permissions.md` and `docs/privacy-model.md`.

---

## Testing conventions

- Unit tests in `tests/unit/` use only fixtures — no real processes or sockets.
- Integration tests in `tests/integration/` bind real sockets and must `pytest.skip`
  if `psutil.net_connections()` raises `AccessDenied`.
- Do not write tests that depend on public internet hosts.
- Every new signal in `FindingEngine` needs a test for the happy path AND a test
  proving it does NOT fire on the benign case.

---

## Common mistakes to avoid

- Adding UI logic to `application/` — the application layer must be renderable by
  any interface (CLI, TUI, future GUI).
- Using `datetime.utcnow()` — use `datetime.now(timezone.utc)` instead (Python 3.13
  deprecates utcnow).
- Hardcoding severity levels in the TUI or CLI.
- Storing cookie values anywhere (even temporarily for debugging).
- Running `psutil.net_connections()` without a try/except for `AccessDenied`.
