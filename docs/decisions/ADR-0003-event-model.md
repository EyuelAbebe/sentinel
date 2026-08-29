# ADR-0003: Event-Driven History

## Status: Accepted

## Context
Saving identical snapshots every poll cycle wastes storage and makes history analysis hard.
We want to know *when* things changed, not just *what* the state is right now.

## Decision
The SnapshotDiffer computes meaningful events (PROCESS_STARTED, PORT_OPENED, etc.)
by diffing consecutive snapshots. Only events (changes) are persisted.

## Consequences
- Polling interval doesn't affect event granularity for stable observations
- Short-lived processes may be missed (documented limitation)
- Future native OS event sources (FSEvents, Endpoint Security) can replace polling
  behind the same collector interface
