from __future__ import annotations

import contextlib
import os
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel
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

_EXPOSURE_SHORT: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]loop[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]local[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]all ⚠[/bold red]",
}


def _classify_user(username: str | None) -> tuple[str, str, str, str]:
    """Return (table name markup, role description, icon, short type)."""
    if not username or username == "(unknown)":
        return ("[dim]unknown[/dim]", "Unknown — no identity", "?", "?")
    u = username.lower()
    if u == "root":
        return (
            "[bold red]root[/bold red]",
            "root — full system privileges, highest risk",
            "[bold red]⬛[/bold red]",
            "[bold red]root[/bold red]",
        )
    if u.startswith("_"):
        return (
            f"[dim]{username}[/dim]",
            f"{username} — macOS system service account",
            "[dim]◆[/dim]",
            "[dim]sys[/dim]",
        )
    if u in _KNOWN_SYSTEM_DAEMONS:
        return (
            f"[dim]{username}[/dim]",
            f"{username} — system daemon",
            "[dim]·[/dim]",
            "[dim]daemon[/dim]",
        )
    if _CURRENT_USER and u == _CURRENT_USER.lower():
        return (
            f"[green]{username}[/green]",
            f"{username} — you (interactive login user)",
            "[green]●[/green]",
            "[green]you[/green]",
        )
    return (
        f"[cyan]{username}[/cyan]",
        f"{username} — standard user",
        "[cyan]◇[/cyan]",
        "[cyan]user[/cyan]",
    )


class UsersScreen(Widget):
    DEFAULT_CSS = """
    UsersScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #users-area {
        height: 1fr;
    }
    #users-table-pane {
        width: 2fr;
        border-right: solid #1a3a5a;
    }
    #users-table {
        height: 1fr;
    }
    #user-detail-pane {
        width: 3fr;
        background: #0d1521;
        color: #a0c8e8;
    }
    #user-detail {
        padding: 1 2;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._correlated: list[CorrelatedProcess] = []
        self._findings: list[Finding] = []
        self._user_rows: list[str] = []

    def compose(self) -> ComposeResult:
        with Horizontal(id="users-area"):
            with Vertical(id="users-table-pane"):
                table: DataTable[str] = DataTable(id="users-table", cursor_type="row")
                table.add_columns("User", "Type", "Procs", "Ports", "Conns", "Issues")
                yield table
            with VerticalScroll(id="user-detail-pane"):
                yield Static(
                    "[dim]Select a user to see their processes and details[/dim]",
                    id="user-detail",
                )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("Enter", "Detail"),
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

        by_user: dict[str, list[CorrelatedProcess]] = {}
        for cp in result.correlated:
            if cp.pid == 0:
                continue
            user = cp.observation.identity.user or "(unknown)"
            by_user.setdefault(user, []).append(cp)

        proc_name_to_user: dict[str, str] = {}
        for cp in result.correlated:
            if cp.pid != 0:
                proc_name_to_user[cp.name] = cp.observation.identity.user or "(unknown)"

        finding_counts: dict[str, int] = {}
        for f in result.findings:
            owner = proc_name_to_user.get(f.subject, "(unknown)")
            finding_counts[owner] = finding_counts.get(owner, 0) + 1

        def sort_key(item: tuple[str, list[CorrelatedProcess]]) -> tuple[int, int]:
            u, procs = item
            is_me = 0 if (_CURRENT_USER and u.lower() == _CURRENT_USER.lower()) else 1
            return (is_me, -len(procs))

        for username, procs in sorted(by_user.items(), key=sort_key):
            name_markup, _, icon, short_type = _classify_user(username)
            port_count = sum(len(cp.listeners) for cp in procs)
            conn_count = sum(len(cp.connections) for cp in procs)
            f_count = finding_counts.get(username, 0)

            find_label = f"[red]{f_count}[/red]" if f_count > 0 else "[green]✓[/green]"
            conn_label = f"[cyan]{conn_count}[/cyan]" if conn_count > 0 else "[dim]0[/dim]"

            idx = len(self._user_rows)
            self._user_rows.append(username)
            table.add_row(
                f"{icon} {name_markup}",
                short_type,
                str(len(procs)),
                str(port_count),
                conn_label,
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

        _, role_str, icon, _ = _classify_user(username)
        flagged_names = {f.subject for f in self._findings}

        pid_set = {cp.pid for cp in procs}
        children: dict[int, list[CorrelatedProcess]] = {}
        for cp in procs:
            ppid = cp.observation.identity.parent_pid
            if ppid and ppid in pid_set:
                children.setdefault(ppid, []).append(cp)

        def proc_order(cp: CorrelatedProcess) -> tuple[int, int, int]:
            return (
                0 if cp.name in flagged_names else 1,
                0 if cp.listeners else 1,
                cp.pid,
            )

        sorted_procs = sorted(procs, key=proc_order)

        total_ports = sum(len(cp.listeners) for cp in procs)
        total_conns = sum(len(cp.connections) for cp in procs)
        total_findings = sum(1 for cp in procs if cp.name in flagged_names)

        lines: list[str] = [
            f"  {icon}  [bold]{username}[/bold]",
            f"  [dim]{role_str}[/dim]",
            "",
            f"  [dim]{len(procs)} processes"
            f"  ·  {total_ports} listening ports"
            f"  ·  {total_conns} connections"
            + (f"  ·  [red]{total_findings} flagged[/red]" if total_findings else ""),
            "",
            "  [bold cyan]── Processes ──────────────────────────────[/bold cyan]",
        ]

        for cp in sorted_procs:
            ppid = cp.observation.identity.parent_pid
            is_child = ppid is not None and ppid in pid_set
            indent = "    " if is_child else "  "
            connector = "[dim]└[/dim]" if is_child else " [dim]·[/dim]"
            child_n = len(children.get(cp.pid, []))
            child_note = f" [dim]+{child_n}↓[/dim]" if child_n else ""

            name_part = f"[red]● {cp.name}[/red]" if cp.name in flagged_names else cp.name

            port_parts: list[str] = []
            for sock in cp.listeners:
                exp = _EXPOSURE_SHORT.get(sock.exposure, "")
                port_parts.append(f":{sock.local_endpoint.port} {exp}")
            port_str = "  " + "  ".join(port_parts) if port_parts else ""

            conn_part = (
                f"  [dim]{len(cp.connections)} conn{'s' if len(cp.connections) != 1 else ''}[/dim]"
                if cp.connections
                else ""
            )

            lines.append(
                f"{indent}{connector} {name_part}"
                f"  [dim]pid {cp.pid}[/dim]"
                f"{child_note}"
                f"{port_str}"
                f"{conn_part}"
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
