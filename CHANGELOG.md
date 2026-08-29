# Changelog

All notable changes to Sentinel are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

**Phase 4a — Storage Foundation**
- `src/sentinel/storage/` module: SQLite-backed persistence via SQLAlchemy 2 (WAL mode)
- `EventRecord` ORM model — stores domain events by type, instance ID, timestamp, and JSON payload
- `FindingRecord` ORM model — stores findings with severity, subject, reasons list, and status
- `EventRepository` — `write()`, `write_many()`, `query_recent()` (filterable by type/time), `count()`
- `FindingRepository` — `write()` (idempotent by `finding_id`), `write_many()`, `query_active()`, `query_all()`, `count_active()`
- `init_db()` — creates all tables from ORM metadata
- 13 unit tests in `tests/unit/test_storage.py` using in-memory SQLite

**Developer tooling**
- `.claude/commands/` — project slash commands: `/project:update-changelog`, `/project:start-phase`, `/project:create-pr`

### Planned
- Phase 4b: `LiveMonitorService` — poll, diff, persist events, emit via EventBus
- Phase 4c: TUI live event feed
- Phase 4: Live monitoring and persistent event history (SQLite + Alembic)
- Phase 5: Identity and classification engine (domain → org → category)
- Phase 6: Baselines and explainable findings
- Phase 7: Deep scan with YARA-X and executable hash caching
- Phase 8: Browser privacy extension (Chrome / Firefox)
- Phase 9: Standalone GUI and local HTTP/WebSocket API

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
- `FindingEngine` with three initial signals: `all_interface_listener`, `local_network_listener`, `suspicious_location`, `executable_missing`
- `QuickScanService` — orchestrates collection, correlation, finding evaluation; returns `ScanResult`
- `sentinel scan` / `sentinel scan quick` — human-readable Rich output
- `sentinel scan --json` — machine-readable JSON (no ANSI codes)
- `sentinel processes` — process table
- `sentinel ports` — listening ports table with exposure badges
- `sentinel network` — active connections table

**Phase 3 — Interactive TUI**
- Textual-based TUI launched by `sentinel` or `sentinel watch`
- **Overview screen**: summary counts (Processes / Ports / Connections / Attention), needs-attention panel, live activity log
- **Apps screen**: sortable DataTable of processes; per-row detail panel (path, user, PPID, ports, command)
- **Network screen**: listeners table + connections table with colour-coded exposure
- **Findings screen**: findings DataTable; expandable reason detail panel
- **Help screen**: full keyboard reference
- Keyboard bindings: `s` rescan, `p` pause, `1–4` tab jump, `?` help, `q` quit
- Auto-refresh every 10 seconds; manual rescan with `s`

### Known limitations
- macOS SIP prevents `psutil.net_connections()` without elevated privileges; ports and connections show partial data for system processes
- Very short-lived processes (< poll interval) may not be detected
- Deep scan, YARA-X, browser extension, baselines, and classification are planned for later phases

[Unreleased]: https://github.com/EyuelAbebe/sentinel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/EyuelAbebe/sentinel/releases/tag/v0.1.0
