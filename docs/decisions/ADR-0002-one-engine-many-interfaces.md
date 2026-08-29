# ADR-0002: One Engine, Multiple Interfaces

## Status: Accepted

## Context
Separate scanning implementations for CLI vs GUI create divergence, duplication, and bugs
where one interface shows different results from another.

## Decision
CLI, TUI, and (eventually) GUI all call the same application services.
There is exactly one implementation of QuickScanService, CorrelationService, and FindingEngine.

## Consequences
- Application layer must have no UI dependency
- Interfaces are thin renderers/wrappers over the same domain model
- Testing the application layer tests all interfaces simultaneously
