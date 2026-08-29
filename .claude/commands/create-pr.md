# create-pr

Create a pull request following project conventions.

## Instructions

1. Run `make fmt && make lint && make typecheck && make test` — all must pass.
2. Run `git log main..HEAD --oneline` to summarise the commits on this branch.
3. Craft the PR title:
   - Imperative mood, ≤ 70 characters
   - No conventional-commit prefix (`feat:`, `fix:` etc.) — plain English only
   - Examples: `add SQLite event store`, `fix exposure classification for IPv6`
4. Craft the PR body using this template:
   ```
   Closes #[issue]

   ## Changes

   - [bullet: what changed and why]
   - [bullet: what changed and why]

   ## Testing

   - [bullet: what tests were added or updated]
   ```
5. Run: `git push origin [branch]`
6. Run: `gh pr create --title "..." --body "..."`
7. After CI is green, merge with: `gh pr merge [number] --squash --delete-branch`
8. Pull main and update CHANGELOG.md.

## Commit message style

- Plain English, imperative: `add event repository`, `fix AccessDenied handling in collector`
- No `WIP`, `fix stuff`, or conventional-commit prefixes
- One logical change per commit
