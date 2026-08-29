# start-phase

Begin a new development phase. Reads the phase plan from CLAUDE.md and sets up the first issue and branch.

## Instructions

1. Read the **Phase state** table in CLAUDE.md to find the current `**Next**` phase.
2. Read `docs/architecture.md` for the relevant layer — understand what will be built.
3. Break the phase into sub-tasks (a, b, c) — each should be a single PR.
4. Create a GitHub issue for the first sub-task:
   - Title: `phase N: [short description of sub-task]`
   - Body: bullet list of what will be implemented + which files will be created/modified
5. Create a feature branch: `feature/phase-N-[short-slug]`
6. Start implementation following the layer dependency rules in CLAUDE.md.
7. After each sub-task is merged, update CHANGELOG.md and start the next sub-task issue.

## Rules

- Never add UI logic to `application/` — it must stay renderable by any interface.
- Every new `FindingEngine` signal needs a happy-path test AND a benign-case test.
- Graceful degradation: every new collector or service catches `AccessDenied` and returns empty, never raises.
- New OS permissions must update `docs/permissions.md` and `docs/privacy-model.md`.
