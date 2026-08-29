# Changelog

All notable changes to Sentinel are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- Phase 4b: `LiveMonitorService` — poll, diff, persist events, emit via EventBus
- Phase 4c: TUI live event feed integration
- Phase 5: Identity and classification engine (domain → org → category)
- Phase 6: Baselines and explainable findings
- Phase 7: Deep scan with YARA-X and executable hash caching
- Phase 8: Browser privacy extension (Chrome / Firefox)
- Phase 9: Standalone GUI and local HTTP/WebSocket API

---

## [0.2.0] — 2026-08-29

### Added

**Phase 4a — Storage Foundation**
- `src/sentinel/storage/` module: SQLite-backed persistence via SQLAlchemy 2 (WAL mode)
- `EventRecord` ORM model — stores domain events by type, instance ID, timestamp, and JSON payload
- `FindingRecord` ORM model — stores findings with severity, subject, reasons list, and status
- `EventRepository` — `write()`, `write_many()`, `query_recent()` (filterable by type/time), `count()`
- `FindingRepository` — `write()` (idempotent by `finding_id`), `write_many()`, `query_active()`, `query_all()`, `count_active()`
- `init_db()` — creates all tables from ORM metadata
- 13 unit tests in `tests/unit/test_storage.py` using in-memory SQLite
- `sqlalchemy>=2.0` and `alembic>=1.13` added as dependencies

**CLI output polish**
- Severity icons in finding panels: `●` HIGH, `◆` MEDIUM, `▲` LOW, `⬛` CRITICAL
- `Rule` separator lines replace plain bold text in scan output
- Finding reasons rendered as `rich.Text` with dim `›` bullet prefix
- Warnings changed from invisible `[dim]` to visible `[yellow]⚠ `
- Port numbers styled `bold cyan` in ports and processes tables
- Remote addresses styled `cyan`, local addresses `dim` in network table

**Documentation**
- `docs/installation.md` — pipx, pip+venv, upgrade, uninstall, launchd service, troubleshooting
- README: Mermaid pipeline diagram, terminal snapshots for `scan`/`ports`/`doctor`, cleaner layout
- GitHub Actions workflow display names improved: `CI — Lint, Test & Smoke`, `Release — Create RC`, `Release — Promote to Production`

**CI**
- CI workflow split into three focused jobs: `quality` (ruff + mypy), `test` (pytest on 3.12 + 3.13), `smoke` (install from wheel + all CLI commands)

**Developer tooling**
- `.claude/commands/` — project slash commands: `/project:update-changelog`, `/project:start-phase`, `/project:create-pr`
- `make smoke` — pre-PR local check: lint + tests + `sentinel scan`
- `make scan` — quick one-shot scan without launching TUI
- `make help` — lists all targets with descriptions
- Makefile uses `.venv/.installed` marker — skips reinstall unless `pyproject.toml`/`poetry.lock` changed
- `make install` calls `poetry env remove --all` before reinstalling to clear stale venv cache

---

## [0.1.0] — 2026-08-29

### Added

**Phase 0 — Bootstrap**
- Python project with `src/` layout, Poetry dependency management, and `poetry.lock`
- `sentinel --help` — command tree
- `sentinel version` — prints installed version from package metadata
- `sentinel doctor` — checks Python version, psutil, rich, textual, pydantic, and optional tools (osquery)
- Structured logging to stderr via Rich; never logs sensitive values
- `SentinelConfig` via Pydantic Settings (env: `SENTINEL_DATA_DIR`, `SENTINEL_LOG_LEVEL`, `SENTINEL_POLL_INTERVAL_SECONDS`)
- Ruff, mypy (strict), pytest, pre-commit configured
- Makefile with `install`, `lint`, `fmt`, `typecheck`, `test`, `bump-patch/minor/major` targets
- Architecture Decision Records: ADR-0001 through ADR-0005
- Initial documentation: README, architecture, privacy-model, threat-model, permissions

**Phase 1 — Domain Core**
- `ProcessIdentity` and `ProcessObservation` with PID-reuse-safe `instance_id` (UUID5 from pid+start_time)
- `NetworkEndpoint` with address, port, protocol, and optional identity/reputation fields
- `SocketObservation` with local/remote endpoints, socket state, and exposure classification
- `Event` model with versioned payload serialization (`payload_version = 1`)
- `Finding` and `FindingReason` with severity, status, reasons list, and evidence references
- `ClassificationEvidence` for domain/IP classification with source and confidence tracking
- Full enum set: `Severity`, `IdentityStatus`, `SecurityStatus`, `PrivacyCategory`, `ExposureLevel`, `SocketState`, `EventType`, `FindingStatus`, `Protocol`
- `CurrentStateRegistry` — in-memory process and socket state
- `SnapshotDiffer` — produces `PROCESS_STARTED/STOPPED`, `PORT_OPENED/CLOSED`, `CONNECTION_OPENED/CLOSED` events
- `EventBus` — in-process async pub/sub

**Phase 2 — Quick Scan**
- `PsutilProcessCollector` — collects all visible processes; skips `AccessDenied` / `NoSuchProcess` gracefully
- `PsutilNetworkCollector` — collects TCP/UDP connections; classifies exposure as `LOOPBACK`, `LOCAL_NETWORK`, or `ALL_INTERFACES`; falls back to empty list on `AccessDenied`
- `CorrelationService` — links socket observations to owning process by PID
- `FindingEngine` with signals: `all_interface_listener`, `local_network_listener`, `suspicious_location`, `executable_missing`
- `QuickScanService` — orchestrates collection, correlation, finding evaluation; returns `ScanResult`
- `sentinel scan` / `sentinel scan quick` — human-readable Rich output
- `sentinel scan --json` — machine-readable JSON (no ANSI codes)
- `sentinel processes` — process table
- `sentinel ports` — listening ports table with exposure badges
- `sentinel network` — active connections table

**Phase 3 — Interactive TUI**
- Textual-based TUI launched by `sentinel` or `sentinel watch`
- **Overview screen**: summary counts, needs-attention panel, live activity log
- **Apps screen**: sortable process table with per-process detail panel
- **Network screen**: listeners + connections tables with colour-coded exposure
- **Findings screen**: findings list with expandable reason detail
- **Help screen**: full keyboard reference
- Keyboard bindings: `s` rescan, `p` pause, `1–4` tab jump, `?` help, `q` quit
- Auto-refresh every 10 seconds; manual rescan with `s`

### Known limitations
- macOS SIP prevents `psutil.net_connections()` without elevated privileges; partial data for system processes
- Very short-lived processes (< poll interval) may not be detected

[Unreleased]: https://github.com/EyuelAbebe/sentinel/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/EyuelAbebe/sentinel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EyuelAbebe/sentinel/releases/tag/v0.1.0
