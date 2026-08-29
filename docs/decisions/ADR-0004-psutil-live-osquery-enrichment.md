# ADR-0004: psutil for Live Collection, osquery for Enrichment

## Status: Accepted

## Context
psutil is fast, cross-platform, and well-maintained. osquery provides richer system
tables (file hashes, launch agents, etc.) but is heavier and optional.

## Decision
- psutil is the primary live collector for processes and network
- osquery is an optional enrichment adapter, queried on-demand for deep scans
- No subprocess parsing of `lsof`, `netstat`, or `ps` in the primary path

## Consequences
- Core monitoring works without osquery installed
- `sentinel doctor` reports osquery availability
- Deep scan quality improves when osquery is present
