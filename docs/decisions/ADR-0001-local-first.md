# ADR-0001: Local-First Architecture

## Status: Accepted

## Context
Security tools that phone home are a privacy and trust risk. Users need to understand
what data is leaving their machine and have the default be no exfiltration.

## Decision
All telemetry collection, storage, and analysis happens on the local machine.
External reputation lookups are explicitly opt-in. No cloud backend in V1.

## Consequences
- No authentication infrastructure needed for V1
- SQLite is sufficient for local storage
- Optional reputation lookups require explicit user action and documentation
