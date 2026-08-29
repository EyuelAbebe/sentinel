# ADR-0005: No Sensitive Browser Data

## Status: Accepted

## Context
Browser extensions have access to cookie values, request bodies, and auth headers.
Storing or logging these would create a local data store that is itself a security risk.

## Decision
- Cookie values are never collected or stored
- Request bodies are never collected
- Authorization and session headers are never logged
- Full URL paths/queries are not persisted; host/domain is sufficient

## Consequences
- Privacy screen shows cookie metadata (name, domain, flags) without values
- Trust surface is limited; the tool cannot itself become a credentials exfiltration vector
- Users can verify behavior by inspecting the local database schema
