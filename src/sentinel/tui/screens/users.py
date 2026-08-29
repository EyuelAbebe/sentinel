from __future__ import annotations

import contextlib
import os
from typing import Any

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.findings import Finding
from sentinel.tui.widgets.key_bar import KeyBar

_CURRENT_USER: str = os.environ.get("USER", "") or os.environ.get("LOGNAME", "")

_KNOWN_SYSTEM_DAEMONS = frozenset(
    {
        "daemon",
        "nobody",
        "www",
        "www-data",
        "man",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "games",
        "ftp",
        "sshd",
        "sync",
        "halt",
        "shutdown",
    }
)


def _classify_user(username: str | None) -> tuple[str, str]:
    """Return (Rich markup label, plain role string)."""
    if not username or username == "(unknown)":
        return ("[dim]unknown[/dim]", "unknown")
    u = username.lower()
    if u == "root":
        return ("[bold red]root — privileged[/bold red]", "System (root)")
    if u.startswith("_"):
        return (f"[dim]{username} — macOS service[/dim]", "macOS system service")
    if u in _KNOWN_SYSTEM_DAEMONS:
        return (f"[dim]{username} — system daemon[/dim]", "System daemon")
    if _CURRENT_USER and u == _CURRENT_USER.lower():
        return (f"[green]{username} — you[/green]", "Interactive user (you)")
    return (f"[cyan]{username}[/cyan]", "User")


class UsersScreen(Widget):
    DEFAULT_CSS = """
    UsersScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #users-table {
        height: 1fr;
        min-height: 8;
    }
    #user-detail {
        height: 12;
        border-top: solid #00ff9f;
        padding: 1 2;
        background: #0d1521;
        color: #a0c8e8;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._correlated: list[CorrelatedProcess] = []
        self._findings: list[Finding] = []
        self._user_rows: list[str] = []

    def compose(self) -> ComposeResult:
        table: DataTable[str] = DataTable(id="users-table", cursor_type="row")
        table.add_columns("!", "User", "Role", "Processes", "Ports", "Findings")
        yield table
        yield Static(
            "[dim]↑ ↓  navigate  ·  select a user to see their processes below[/dim]",
            id="user-detail",
        )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("s", "Rescan"),
                ("1-7", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def on_show(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#users-table", DataTable).focus()

    def update_result(self, result: ScanResult) -> None:
        self._correlated = result.correlated
        self._findings = result.findings

        table = self.query_one("#users-table", DataTable)
        table.clear()
        self._user_rows = []

        # Group processes by user
        by_user: dict[str, list[CorrelatedProcess]] = {}
        for cp in result.correlated:
            if cp.pid == 0:
                continue
            user = cp.observation.identity.user or "(unknown)"
            by_user.setdefault(user, []).append(cp)

        # Count findings per user (by matching process name to subject)
        proc_name_to_user: dict[str, str] = {}
        for cp in result.correlated:
            if cp.pid != 0:
                proc_name_to_user[cp.name] = cp.observation.identity.user or "(unknown)"

        finding_counts: dict[str, int] = {}
        for f in result.findings:
            owner = proc_name_to_user.get(f.subject, "(unknown)")
            finding_counts[owner] = finding_counts.get(owner, 0) + 1

        # Sort: current user first, then by process count descending
        def sort_key(item: tuple[str, list[CorrelatedProcess]]) -> tuple[int, int]:
            u, procs = item
            is_me = 0 if (_CURRENT_USER and u.lower() == _CURRENT_USER.lower()) else 1
            return (is_me, -len(procs))

        for username, procs in sorted(by_user.items(), key=sort_key):
            role_markup, _ = _classify_user(username)
            port_count = sum(len(cp.listeners) for cp in procs)
            f_count = finding_counts.get(username, 0)

            flag = "[bold red]⚠[/bold red]" if f_count > 0 else ""
            find_label = f"[red]{f_count}[/red]" if f_count > 0 else "[green]✓[/green]"

            idx = len(self._user_rows)
            self._user_rows.append(username)
            table.add_row(
                flag,
                username,
                role_markup,
                str(len(procs)),
                str(port_count),
                find_label,
                key=str(idx),
            )

    def _render_detail(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._user_rows):
            return
        username = self._user_rows[idx]
        procs = [
            cp
            for cp in self._correlated
            if (cp.observation.identity.user or "(unknown)") == username and cp.pid != 0
        ]

        _, role_str = _classify_user(username)

        # Which of this user's processes have findings?
        flagged_names = {f.subject for f in self._findings}

        # Build subprocess map: parent_pid → list[child]
        pid_set = {cp.pid for cp in procs}
        children: dict[int, list[CorrelatedProcess]] = {}
        for cp in procs:
            ppid = cp.observation.identity.parent_pid
            if ppid and ppid in pid_set:
                children.setdefault(ppid, []).append(cp)

        # Sort: procs with open ports or findings first, then by pid
        def proc_order(cp: CorrelatedProcess) -> tuple[int, int, int]:
            return (
                0 if cp.name in flagged_names else 1,
                0 if cp.listeners else 1,
                cp.pid,
            )

        sorted_procs = sorted(procs, key=proc_order)

        lines: list[str] = [
            f"[bold]{username}[/bold]  [dim]— {role_str}[/dim]",
            f"[dim]{len(procs)} processes  ·  "
            f"{sum(len(cp.listeners) for cp in procs)} ports  ·  "
            f"{sum(len(cp.connections) for cp in procs)} connections[/dim]",
            "",
        ]

        for shown, cp in enumerate(sorted_procs):
            if shown >= 7:
                remaining = len(procs) - shown
                lines.append(
                    f"  [dim]… {remaining} more process{'es' if remaining != 1 else ''}[/dim]"
                )
                break

            ports = ", ".join(f":{s.local_endpoint.port}" for s in cp.listeners)
            child_n = len(children.get(cp.pid, []))
            child_note = (
                f"  [dim]+{child_n} child{'ren' if child_n != 1 else ''}[/dim]" if child_n else ""
            )
            port_note = f"  [cyan]{ports}[/cyan]" if ports else ""

            ppid = cp.observation.identity.parent_pid
            is_child = ppid is not None and ppid in pid_set
            indent = "    " if is_child else "  "
            connector = "[dim]└[/dim] " if is_child else "[dim]·[/dim] "
            name_part = f"[red]● {cp.name}[/red]" if cp.name in flagged_names else cp.name

            lines.append(
                f"{indent}{connector}{name_part}  [dim]pid {cp.pid}[/dim]{port_note}{child_note}"
            )

        with contextlib.suppress(Exception):
            self.query_one("#user-detail", Static).update("\n".join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        self._render_detail(int(event.row_key.value))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        self._render_detail(int(event.row_key.value))
