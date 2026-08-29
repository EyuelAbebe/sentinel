# Sentinel

Local security and privacy monitoring for macOS. Sentinel watches running processes, open ports, and network connections and surfaces anything unusual — no root access, no cloud account, no noise.

---

## Install

**Requires:** macOS 14+, Python 3.12+

```bash
# CLI only (scan, processes, ports, network)
pipx install sentinel

# CLI + interactive TUI
pipx install "sentinel[tui]"
```

Verify the install:

```bash
sentinel doctor
```

> To install from source, see [docs/contributing.md](docs/contributing.md).

---

## Usage

```bash
sentinel scan              # quick security scan
sentinel scan --json       # machine-readable JSON output
sentinel processes         # table of running processes
sentinel ports             # listening ports with exposure level
sentinel network           # active connections
sentinel doctor            # check environment and tool availability
sentinel version           # show installed version
sentinel                   # open interactive TUI  (requires sentinel[tui])
```

---

## Example output

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

Sentinel explains *why* something is flagged. Every finding shows the signals that triggered it.

---

## What gets flagged

| Signal | Severity |
|---|---|
| Process listening on all interfaces (`0.0.0.0` / `::`) | MEDIUM |
| Process listening on all interfaces + running from suspicious path | HIGH |
| Executable running from `~/Downloads`, `/tmp`, `/var/tmp` | MEDIUM |
| Process running but executable no longer exists on disk | HIGH |

---

## Permissions

Sentinel runs without root. Some data is limited by macOS SIP:

| Feature | Without root | With root (`sudo sentinel`) |
|---|---|---|
| Process list | User processes + partial system | All processes |
| Ports & connections | Partial | Full |

---

## Documentation

| Doc | Description |
|---|---|
| [Architecture](docs/architecture.md) | Layer diagram, scan pipeline, dependency rules |
| [Contributing](docs/contributing.md) | Dev setup, branching, PR process |
| [Release process](docs/release-process.md) | How RCs and production releases work |
| [Privacy model](docs/privacy-model.md) | What data is collected and how |
| [Permissions](docs/permissions.md) | OS permissions used and why |
| [Threat model](docs/threat-model.md) | Known threats against Sentinel itself |

---

## License

MIT — see [LICENSE](LICENSE).
