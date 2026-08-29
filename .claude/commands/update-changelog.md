# update-changelog

Update CHANGELOG.md with the work done in the current session.

## Instructions

1. Run `git log main..HEAD --oneline` to see commits not yet on main, and `git log --oneline -10` to see recent merged work.
2. Identify which phase these changes belong to (check CLAUDE.md Phase state table).
3. Open CHANGELOG.md and find the correct section:
   - If the version is already released, changes go under `## [Unreleased]`
   - If we just merged work for a new release, create a new `## [x.y.z]` section
4. Add bullet points for every meaningful addition, change, or fix.
   - Group under `### Added`, `### Changed`, or `### Fixed`
   - Lead each bullet with the phase tag, e.g. `**Phase 4 — Live Monitoring**`
   - Be specific: name the service, file, or behaviour changed
5. Update the comparison links at the bottom of the file.
6. Commit with message: `docs: update CHANGELOG for [version or phase]`

## Format reference

```markdown
## [Unreleased]

### Added

**Phase 4 — Live Monitoring + Persistence**
- `LiveMonitorService` — polls QuickScanService on a configurable interval
- SQLite event store via SQLAlchemy + Alembic migrations
- `EventRepository` — persists domain events; queries by time range and type
```
