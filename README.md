# Sentinel

[![CI](https://github.com/EyuelAbebe/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/EyuelAbebe/sentinel/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Know what's running on your Mac.**

Sentinel watches your processes, open ports, and network connections in real time. When something looks unusual — a process listening on all interfaces, an executable running from your Downloads folder, a binary that no longer exists on disk — it tells you exactly what it found and why.

No cloud account. No root access. No noise.

---

## What it does

```
Security Scan Complete

  Processes   Listening ports   Connections   Attention
 ─────────────────────────────────────────────────────
        231                14            42           1

╭─ ! unknown-helper  HIGH ──────────────────────────────────╮
│   Running from /Users/you/Downloads/unknown-helper        │
│   Listening on :4444 (TCP) — accessible from all          │
│   network interfaces                                      │
╰───────────────────────────────────────────────────────────╯
```

Every finding explains **why** it was flagged. Sentinel never says "unknown = dangerous" — it shows you the signals and lets you decide.

---

## Install

**Requires:** macOS 14+, Python 3.12+

The recommended way is [pipx](https://pipx.pypa.io), which isolates Sentinel from your system Python and puts `sentinel` on your PATH:

```bash
# CLI + interactive TUI (recommended)
pipx install "sentinel[tui]"

# CLI only (scan, processes, ports, network — no interactive monitor)
pipx install sentinel
```

Verify everything works:

```bash
sentinel doctor
```

> **Want to run Sentinel automatically on login?** See [docs/installation.md](docs/installation.md) for launchd service setup, pip/virtualenv install, and upgrade instructions.

---

## Quick start

```bash
sentinel scan              # security scan with findings
sentinel                   # open the interactive monitor
```

---

## Commands

| Command | Description |
|---|---|
| `sentinel scan` | Security scan — processes, ports, findings |
| `sentinel scan --json` | Same, machine-readable JSON (no ANSI) |
| `sentinel processes` | Table of running processes |
| `sentinel ports` | Listening ports with exposure level |
| `sentinel network` | Active outbound connections |
| `sentinel doctor` | Check environment and tool availability |
| `sentinel version` | Show installed version |
| `sentinel` | Open interactive TUI monitor |

---

## What gets flagged

| Signal | Why it matters | Severity |
|---|---|---|
| Listening on all interfaces (`0.0.0.0` / `::`) | Accessible from your entire network | MEDIUM |
| Listening on all interfaces + suspicious path | Unexpected binary exposed to network | HIGH |
| Running from `~/Downloads`, `/tmp`, `/var/tmp` | Executables rarely live here legitimately | MEDIUM |
| Executable no longer exists on disk | Process running from a deleted file | HIGH |

---

## Permissions

Sentinel runs as a normal user — no root, no admin, no special entitlements. Some data is limited by macOS System Integrity Protection:

| What you get | Without root | With `sudo sentinel` |
|---|---|---|
| Your own processes | All | All |
| System processes | Partial | All |
| Port owners for SIP-protected processes | Partial | All |
| Connections for SIP-protected processes | Partial | All |

Run `sentinel doctor` to see exactly what is visible in your environment.

---

## Docs

| Document | What's inside |
|---|---|
| [Installation guide](docs/installation.md) | pipx, pip, launchd service, upgrade, uninstall |
| [Contributing](docs/contributing.md) | Dev setup, branching, PR process, architecture rules |
| [Release process](docs/release-process.md) | How RC tags and production releases work |
| [Architecture](docs/architecture.md) | Layer diagram, scan pipeline, design decisions |
| [Privacy model](docs/privacy-model.md) | What data is collected, stored, and never stored |
| [Threat model](docs/threat-model.md) | Known threats against Sentinel itself |
| [Permissions](docs/permissions.md) | Every OS permission used and why |

---

## License

MIT — see [LICENSE](LICENSE).
