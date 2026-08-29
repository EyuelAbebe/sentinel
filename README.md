# Sentinel

[![CI](https://github.com/EyuelAbebe/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/EyuelAbebe/sentinel/actions/workflows/ci.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**Know what's running on your Mac.**

Sentinel watches your processes, open ports, and network connections. When something looks unusual it tells you exactly what it found and **why** — no cloud account, no root access, no noise.

---

## Live monitor preview

```
 Sentinel  —  Local Security Monitor                              14:32:19
 ─────────────────────────────────────────────────────────────────────────
  1 Overview   2 Apps   3 Network   4 Findings
 ─────────────────────────────────────────────────────────────────────────

  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │ ⬤ PROCESSES  │  │   ◆ PORTS    │  │ ⇄ CONNECTIONS│  │  ● ATTENTION │
  │     231      │  │      14      │  │      42      │  │      1  ⚠    │
  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘

  ⚠  1 finding needs attention  ·  scanned 14:32:06  (1.4s)

  ── NEEDS ATTENTION ────────────────────────────────────────────────────
  ● HIGH  unknown-helper
          subject: unknown-helper (pid 4521)
          ›  Running from /Users/you/Downloads/unknown-helper
          ›  Listening on :4444 (TCP) — all interfaces

  ── LIVE ACTIVITY ──────────────────────────────────────────────────────
  14:32:07  ⬆ PROC   Chrome Helper (pid 8831)
  14:32:05  → CONN   35.190.27.0:443
  14:32:03  ◆ PORT   nginx :443 opened

 ─────────────────────────────────────────────────────────────────────────
  s  Rescan    p  Pause    1-4  Tabs    ?  Help    q  Quit
```

---

## Install

**Requires macOS 14+, Python 3.12+**

```bash
git clone https://github.com/EyuelAbebe/sentinel.git
cd sentinel
pip install poetry && poetry install
```

Verify:

```bash
poetry run sentinel doctor
```

> For pip, pipx, launchd auto-start, and upgrade instructions see [docs/installation.md](docs/installation.md).

---

## Quick start

```bash
poetry run sentinel scan        # one-shot security scan
poetry run sentinel             # open interactive live monitor (TUI)
poetry run sentinel serve       # start HTTP API + browser dashboard on :7173
```

Or activate the virtualenv once: `source .venv/bin/activate`, then just `sentinel <cmd>`.

---

## How it works

```mermaid
flowchart LR
    subgraph Sources[" Data Sources "]
        P([Processes])
        S([Sockets])
    end

    subgraph Core[" Sentinel Core "]
        C[Correlator]
        F[Finding Engine]
    end

    subgraph Out[" Interfaces "]
        CLI(CLI)
        TUI(TUI)
        API(API · Browser)
    end

    P & S -->|psutil| C --> F --> CLI & TUI & API
```

Each scan correlates every open socket back to its owning process. The finding engine evaluates signals against the correlated data — it never flags something without a concrete reason.

<details>
<summary>Scan pipeline</summary>

```mermaid
sequenceDiagram
    participant U  as Trigger
    participant SS as ScanService
    participant PC as ProcessCollector
    participant NC as NetworkCollector
    participant FE as FindingEngine

    U  ->>  SS : run()
    SS ->>  PC : collect()
    SS ->>  NC : collect()
    PC -->> SS : [ProcessObservation]
    NC -->> SS : [SocketObservation]
    SS ->>  SS : correlate()
    SS ->>  FE : evaluate(correlated)
    FE -->> SS : [Finding]
    SS -->> U  : ScanResult
```

</details>

---

## What gets flagged

| Signal | Severity |
|---|---|
| Listening on all interfaces (`0.0.0.0` / `::`) | MEDIUM |
| All-interfaces listener + suspicious executable path | HIGH |
| Running from `~/Downloads`, `/tmp`, `/var/tmp` | MEDIUM |
| Executable no longer exists on disk | HIGH |
| Known tracker connection | LOW |

Every finding shows the exact signals that triggered it. Sentinel never says "unknown = dangerous."

---

<details>
<summary><strong>CLI reference</strong></summary>

```
$ sentinel scan

 ──────────────── Sentinel  Quick Scan · 14:32:06 (1.4s) ────────────────

  Processes   Ports   Connections   Attention
 ─────────────────────────────────────────────
       231      14            42        1 ⚠

 ╭─ ● HIGH  unknown-helper ──────────────────────────────────────────╮
 │  › Running from /Users/you/Downloads/                              │
 │  › Listening on :4444 (TCP) — all interfaces                       │
 ╰────────────────────────────────────────────────────────────────────╯

  Run sentinel watch for live interactive monitoring
```

| Command | What it does |
|---|---|
| `sentinel scan` | Security scan with findings |
| `sentinel scan --json` | Machine-readable JSON output (no ANSI) |
| `sentinel scan deep` | Deep scan: hash integrity + YARA rules |
| `sentinel processes` | Table of all running processes |
| `sentinel ports` | Listening ports with exposure levels |
| `sentinel network` | Active outbound connections |
| `sentinel baseline list` | Show baseline entries |
| `sentinel baseline add --process nginx --reason "web server"` | Suppress a known process |
| `sentinel baseline add --port 8080 --reason "dev server"` | Suppress a known port |
| `sentinel baseline remove <id>` | Remove a baseline entry |
| `sentinel serve` | Start HTTP API + browser dashboard on `:7173` |
| `sentinel doctor` | Check environment and tool availability |
| `sentinel version` | Show installed version |

```
$ sentinel ports

 Listening Ports
 ──────────────────────────────────────────────────────────
    Port   Protocol  Process       PID    Exposure
 ──────────────────────────────────────────────────────────
    22     TCP       sshd          891    Localhost only
  ⚠ 443    TCP       nginx         2341   All interfaces
    5432   TCP       postgres      3812   Localhost only
```

```
$ sentinel doctor

 Environment
 ───────────────────────────────────────────────────────────────
  Check               Status   Detail
 ───────────────────────────────────────────────────────────────
  Python ≥ 3.12       OK       3.13.1
  psutil              OK       6.0.0
  rich                OK       13.9.4
  textual             OK       0.80.1
  pydantic            OK       2.9.2
  osquery (optional)  MISSING  not found
```

</details>

---

<details>
<summary><strong>Interactive TUI monitor</strong></summary>

Run `sentinel` (or `sentinel watch`) to open the live monitor. Dark neon theme — no config required.

**Overview tab**

```
 Sentinel  —  Local Security Monitor                              14:32:19
 ─────────────────────────────────────────────────────────────────────────
  1 Overview   2 Apps   3 Network   4 Findings
 ─────────────────────────────────────────────────────────────────────────

  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
  │ ⬤ PROCESSES  │  │   ◆ PORTS    │  │ ⇄ CONNECTIONS│  │  ● ATTENTION │
  │     231      │  │      14      │  │      42      │  │      1  ⚠    │
  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘

  ⚠  1 finding needs attention  ·  scanned 14:32:06  (1.4s)

  ── NEEDS ATTENTION ────────────────────────────────────────────────────
  ● HIGH  unknown-helper
          subject: unknown-helper (pid 4521)
          ›  Running from /Users/you/Downloads/unknown-helper
          ›  Listening on :4444 (TCP) — all interfaces

  ── LIVE ACTIVITY ──────────────────────────────────────────────────────
  14:32:07  ⬆ PROC   Chrome Helper (pid 8831)
  14:32:05  → CONN   35.190.27.0:443
  14:32:03  ◆ PORT   nginx :443 opened

 ─────────────────────────────────────────────────────────────────────────
  s  Rescan    p  Pause    1-4  Tabs    ?  Help    q  Quit
```

**Apps tab** — all running processes; flag icon shows worst finding

```
  ─────────────────────────────────────────────────────────────────────────
  !    PID    Name                  User     Ports     Path
  ─────────────────────────────────────────────────────────────────────────
  ●    4521   unknown-helper        eyuel    :4444     /Users/you/Downloads/
       891    sshd                  root     :22       /usr/sbin/sshd
       2341   nginx                 www      :443      /usr/local/bin/nginx
  ─────────────────────────────────────────────────────────────────────────
  unknown-helper  PID 4521
  ● HIGH  Suspicious executable location
    › Running from /Users/you/Downloads/unknown-helper
    › Listening on :4444 (TCP) — all interfaces
  Path    /Users/you/Downloads/unknown-helper
  User    eyuel   PPID  1
  ─────────────────────────────────────────────────────────────────────────
  ↑↓  Navigate    Enter  Inspect    s  Rescan    ?  Help    q  Quit
```

**Tabs**

| Tab | What it shows |
|---|---|
| **1 Overview** | Stat bar, scan status, findings grouped by severity, live activity stream |
| **2 Apps** | All processes; `●` `◆` `▲` icons flag severity; Enter to inspect |
| **3 Network** | Listening ports (`⚠` = all-interfaces) + active connections |
| **4 Findings** | All findings sorted worst-first; Enter for full detail panel |

**Key bindings**

| Key | Action |
|---|---|
| `1` `2` `3` `4` | Switch tabs |
| `Tab` / `Shift-Tab` | Cycle tabs |
| `↑` `↓` | Navigate rows |
| `Enter` | Inspect selected row |
| `s` | Rescan now |
| `p` | Pause / resume live monitoring |
| `?` | Open help screen |
| `q` | Quit |

</details>

---

<details>
<summary><strong>Browser dashboard</strong></summary>

Run `sentinel serve` then open **http://localhost:7173** in any browser. No login, no setup.

```
 ┌─ SENTINEL  Live Dashboard ──────────────────────── ● live ─── ↺ Scan ─┐
 │                                                                         │
 │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
 │  │ ⬤ Processes │  │   ◆ Ports   │  │ ⇄ Connections│  │ ● Attention │   │
 │  │     231     │  │      14     │  │      42      │  │      1      │   │
 │  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
 │                                                                         │
 │  ┌── Needs Attention ──────────────┐  ┌── Listening Ports ───────────┐  │
 │  │  HIGH  unknown-helper           │  │  ⚠  :4444  TCP  unknown-helper│  │
 │  │  pid 4521 · /Downloads/         │  │     :22    TCP  sshd          │  │
 │  │  › All-interfaces listener      │  │     :5432  TCP  postgres      │  │
 │  └─────────────────────────────────┘  └──────────────────────────────┘  │
 │                                                                         │
 │  ┌── Live Activity ──────────────────────────────────────────────────┐  │
 │  │  14:32:07  PROCESS_STARTED   Chrome Helper (pid 8831)             │  │
 │  │  14:32:05  CONNECTION_OPENED  → 35.190.27.0:443                   │  │
 │  │  14:32:03  PORT_OPENED        nginx :443                          │  │
 │  └───────────────────────────────────────────────────────────────────┘  │
 └─────────────────────────────────────────────────────────────────────────┘
```

**API endpoints** (all on the same port):

| Endpoint | Description |
|---|---|
| `GET /` | Browser dashboard |
| `GET /scan` | Run scan and return JSON |
| `GET /findings` | Query persisted findings from SQLite |
| `GET /baseline` | List baseline entries |
| `GET /health` | Liveness probe |
| `WS /events` | Stream live domain events |

Connects to `WS /events` for real-time updates; polls `/scan` every 30 seconds. Auto-reconnects on disconnect. Dark mode via `prefers-color-scheme`.

</details>

---

## Permissions

Sentinel runs as a normal user — no root, no admin, no special entitlements.

| What | Without root | With `sudo` |
|---|---|---|
| Your own processes | All | All |
| System processes | Partial | All |
| Port owners (SIP-protected) | Partial | All |

Run `sentinel doctor` to see exactly what is visible in your environment.

---

## Docs

| | |
|---|---|
| [Installation guide](docs/installation.md) | Source install, pip, pipx, launchd, upgrade |
| [Contributing](docs/contributing.md) | Dev setup, branching, PR process |
| [Architecture](docs/architecture.md) | Layer diagram, scan pipeline, design decisions |
| [Privacy model](docs/privacy-model.md) | What is and isn't collected or stored |
| [Release process](docs/release-process.md) | RC and production release workflow |

---

## License

MIT — see [LICENSE](LICENSE).
