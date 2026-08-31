from __future__ import annotations

import contextlib
import ipaddress
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.events import Key
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel
from sentinel.tui.widgets.key_bar import KeyBar

_EXPOSURE_LABEL: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]Localhost[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]Local net[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]All ifaces ⚠[/bold red]",
}

_EXPOSURE_FLAG: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]✓[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]◆[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]⚠[/bold red]",
}


def _classify_remote(address: str | None) -> str:
    if not address:
        return "[dim]—[/dim]"
    try:
        ip = ipaddress.ip_address(address)
        if ip.is_loopback:
            return "[green]loopback[/green]"
        if ip.is_private:
            return "[yellow]local-net[/yellow]"
        if ip.is_global:
            return "[cyan]external[/cyan]"
        if ip.is_link_local:
            return "[dim]link-local[/dim]"
    except ValueError:
        pass
    return "[dim]unknown[/dim]"


class NetworkScreen(Widget):
    DEFAULT_CSS = """
    NetworkScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #tables-area {
        height: 1fr;
    }
    #listeners-pane {
        width: 1fr;
        border-right: solid #1a3a5a;
    }
    #connections-pane {
        width: 1fr;
    }
    .section-label {
        height: 1;
        padding: 0 1;
        color: #00e5ff;
        text-style: bold;
        background: #080e18;
    }
    #listeners-table {
        height: 1fr;
    }
    #connections-table {
        height: 1fr;
    }
    #net-detail-scroll {
        height: 7;
        border-top: solid #00ff9f;
        background: #0d1521;
        color: #a0c8e8;
    }
    #net-detail {
        padding: 1 2;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._listener_rows: list[tuple[CorrelatedProcess, Any]] = []
        # Each group: {pid, name, cp, connections: list[tuple[cp, conn, conn_type]]}
        self._conn_groups: list[dict[str, Any]] = []
        self._conn_expanded: set[int] = set()
        self._current_conn_key: str | None = None

    def compose(self) -> ComposeResult:
        with Horizontal(id="tables-area"):
            with Vertical(id="listeners-pane"):
                yield Static(
                    "── LISTENING PORTS ──",
                    classes="section-label",
                    id="listeners-label",
                )
                listeners: DataTable[str] = DataTable(id="listeners-table", cursor_type="row")
                listeners.add_columns("!", "Port", "Proto", "Process", "Exposure")
                yield listeners
            with Vertical(id="connections-pane"):
                yield Static(
                    "── ACTIVE CONNECTIONS ──",
                    classes="section-label",
                    id="connections-label",
                )
                conns: DataTable[str] = DataTable(id="connections-table", cursor_type="row")
                conns.add_columns("Process", "Local", "Remote", "Type", "State")
                yield conns
        with VerticalScroll(id="net-detail-scroll"):
            yield Static(
                "[dim]↑ ↓  navigate  ·  Enter  expand/collapse  ·  Tab  switch panes[/dim]",
                id="net-detail",
            )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("Enter", "Expand"),
                ("Tab", "Switch"),
                ("s", "Rescan"),
                ("1-7", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def on_show(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#listeners-table", DataTable).focus()

    def on_key(self, event: Key) -> None:
        focused = self.app.focused
        if not isinstance(focused, DataTable) or focused.id != "connections-table":
            return
        if event.key not in ("right", "left"):
            return
        key = self._current_conn_key
        if not key:
            return
        if key.startswith("h:"):
            pid = int(key[2:])
            if event.key == "right":
                self._conn_expanded.add(pid)
            else:
                self._conn_expanded.discard(pid)
            self._render_connections_table(restore_key=key)
            event.stop()
        elif key.startswith("c:") and event.key == "left":
            pid = int(key.split(":")[1])
            self._conn_expanded.discard(pid)
            self._render_connections_table(restore_key=f"h:{pid}")
            event.stop()

    def update_result(self, result: ScanResult) -> None:
        # ── Listeners ────────────────────────────────────────────────────────
        listeners_table = self.query_one("#listeners-table", DataTable)
        listeners_table.clear()
        self._listener_rows = []
        for cp in result.correlated:
            for sock in cp.listeners:
                idx = len(self._listener_rows)
                self._listener_rows.append((cp, sock))
                listeners_table.add_row(
                    _EXPOSURE_FLAG.get(sock.exposure, ""),
                    str(sock.local_endpoint.port),
                    sock.local_endpoint.protocol.upper(),
                    cp.name,
                    _EXPOSURE_LABEL.get(sock.exposure, str(sock.exposure)),
                    key=str(idx),
                )

        # ── Connections grouped by process ───────────────────────────────────
        seen: set[int] = set()
        groups: list[dict[str, Any]] = []
        for cp in result.correlated:
            if not cp.connections or cp.pid in seen:
                continue
            seen.add(cp.pid)
            items = [
                (
                    cp,
                    conn,
                    _classify_remote(
                        conn.remote_endpoint.address if conn.remote_endpoint else None
                    ),
                )
                for conn in cp.connections
            ]
            groups.append({"pid": cp.pid, "name": cp.name, "cp": cp, "connections": items})
        groups.sort(key=lambda g: len(g["connections"]), reverse=True)
        self._conn_groups = groups
        self._render_connections_table()

        n_l = len(self._listener_rows)
        n_c = sum(len(g["connections"]) for g in groups)
        n_p = len(groups)
        self.query_one("#listeners-label", Static).update(
            f"── LISTENING PORTS ({n_l})"
            f"  [dim][bold red]⚠[/bold red]=all  [yellow]◆[/yellow]=local  [green]✓[/green]=loop[/dim]"
        )
        self.query_one("#connections-label", Static).update(
            f"── ACTIVE CONNECTIONS ({n_c})"
            f"  [dim]{n_p} processes  ·  [bold]→[/bold] expand  [bold]←[/bold] collapse[/dim]"
        )
        if n_l == 0 and n_c == 0:
            with contextlib.suppress(Exception):
                self.query_one("#net-detail", Static).update(
                    "[yellow]No network data visible.[/yellow]\n\n"
                    "[dim]macOS restricts socket visibility without elevated privileges.\n"
                    "Run  [bold]sudo sentinel[/bold]  for complete network data.\n"
                    "Press  [bold]s[/bold]  to rescan.[/dim]"
                )

    def _render_connections_table(self, restore_key: str | None = None) -> None:
        table = self.query_one("#connections-table", DataTable)
        saved = restore_key or self._current_conn_key
        table.clear()
        for group in self._conn_groups:
            pid = group["pid"]
            n = len(group["connections"])
            is_exp = pid in self._conn_expanded
            arrow = "[bold cyan]▼[/bold cyan]" if is_exp else "[dim]▶[/dim]"
            table.add_row(
                f"{arrow} {group['name']}",
                f"[dim]pid {pid}[/dim]",
                f"[dim]{n} connection{'s' if n != 1 else ''}[/dim]",
                "",
                "",
                key=f"h:{pid}",
            )
            if is_exp:
                for i, (_cp, conn, conn_type) in enumerate(group["connections"]):
                    remote_str = (
                        f"{conn.remote_endpoint.address}:{conn.remote_endpoint.port}"
                        if conn.remote_endpoint
                        else "—"
                    )
                    table.add_row(
                        "  [dim]└[/dim]",
                        f"[dim]{conn.local_endpoint.address}:{conn.local_endpoint.port}[/dim]",
                        remote_str,
                        conn_type,
                        conn.socket_state.upper(),
                        key=f"c:{pid}:{i}",
                    )
        if saved:
            fallback = f"h:{saved.split(':')[1]}" if saved.startswith("c:") else None
            self._cursor_to_key(table, saved, fallback)

    def _cursor_to_key(
        self, table: DataTable[str], target: str, fallback: str | None = None
    ) -> None:
        keys = list(table.rows.keys())
        for i, k in enumerate(keys):
            if k.value == target:
                with contextlib.suppress(Exception):
                    table.move_cursor(row=i)
                return
        if fallback:
            for i, k in enumerate(keys):
                if k.value == fallback:
                    with contextlib.suppress(Exception):
                        table.move_cursor(row=i)
                    return

    # ── Detail panel ─────────────────────────────────────────────────────────

    def _render_listener_detail(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._listener_rows):
            return
        cp, sock = self._listener_rows[idx]
        lines = [
            f"[bold]:{sock.local_endpoint.port}[/bold]"
            f"  [dim]{sock.local_endpoint.protocol.upper()}[/dim]"
            f"  ·  [dim]owned by[/dim] [bold]{cp.name}[/bold]  [dim](PID {cp.pid})[/dim]"
            f"  ·  {_EXPOSURE_LABEL.get(sock.exposure, str(sock.exposure))}",
            f"  [dim]Bind[/dim]  {sock.local_endpoint.address}",
        ]
        if cp.observation.identity.executable_path:
            lines.append(f"  [dim]Path[/dim]  {cp.observation.identity.executable_path}")
        if cp.observation.identity.user:
            lines.append(f"  [dim]User[/dim]  {cp.observation.identity.user}")
        with contextlib.suppress(Exception):
            self.query_one("#net-detail", Static).update("\n".join(lines))

    def _render_conn_header_detail(self, pid: int) -> None:
        group = next((g for g in self._conn_groups if g["pid"] == pid), None)
        if not group:
            return
        n = len(group["connections"])
        is_exp = pid in self._conn_expanded
        type_counts: dict[str, int] = {}
        for _, _conn, ctype in group["connections"]:
            clean = (
                ctype.replace("[cyan]", "")
                .replace("[/cyan]", "")
                .replace("[yellow]", "")
                .replace("[/yellow]", "")
                .replace("[green]", "")
                .replace("[/green]", "")
                .replace("[dim]", "")
                .replace("[/dim]", "")
                .strip()
            )
            type_counts[clean] = type_counts.get(clean, 0) + 1
        summary = "  ".join(
            f"{v}× {k}" for k, v in sorted(type_counts.items(), key=lambda x: -x[1])
        )
        identity = group["cp"].observation.identity
        hint = (
            "[bold]←[/bold] collapse"
            if is_exp
            else "[bold]→[/bold] expand  ·  [bold]Enter[/bold] toggle"
        )
        lines = [
            f"[bold]{group['name']}[/bold]  [dim](PID {pid})[/dim]"
            f"  ·  {n} connection{'s' if n != 1 else ''}",
            f"  [dim]{summary}[/dim]",
        ]
        if identity.user:
            lines.append(f"  [dim]User[/dim]  {identity.user}")
        if identity.executable_path:
            lines.append(f"  [dim]Path[/dim]  {identity.executable_path}")
        lines.append(f"  [dim]{hint}[/dim]")
        with contextlib.suppress(Exception):
            self.query_one("#net-detail", Static).update("\n".join(lines))

    def _render_conn_child_detail(self, pid: int, idx: int) -> None:
        group = next((g for g in self._conn_groups if g["pid"] == pid), None)
        if not group or idx >= len(group["connections"]):
            return
        _cp, conn, conn_type = group["connections"][idx]
        remote_str = (
            f"{conn.remote_endpoint.address}:{conn.remote_endpoint.port}"
            if conn.remote_endpoint
            else "—"
        )
        lines = [
            f"[bold]{group['name']}[/bold]  [dim](PID {pid})[/dim]"
            f"  ·  {conn.socket_state.upper()}  ·  {conn_type}",
            f"  [dim]Local[/dim]   {conn.local_endpoint.address}:{conn.local_endpoint.port}",
            f"  [dim]Remote[/dim]  {remote_str}",
            f"  [dim]Proto[/dim]   {conn.local_endpoint.protocol.upper()}",
        ]
        if _cp.observation.identity.executable_path:
            lines.append(f"  [dim]Path[/dim]    {_cp.observation.identity.executable_path}")
        with contextlib.suppress(Exception):
            self.query_one("#net-detail", Static).update("\n".join(lines))

    # ── Event handlers ────────────────────────────────────────────────────────

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        key = event.row_key.value
        if event.control.id == "listeners-table":
            with contextlib.suppress(ValueError):
                self._render_listener_detail(int(key))
        elif event.control.id == "connections-table":
            self._current_conn_key = key
            if key.startswith("h:"):
                self._render_conn_header_detail(int(key[2:]))
            elif key.startswith("c:"):
                parts = key.split(":")
                self._render_conn_child_detail(int(parts[1]), int(parts[2]))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        key = event.row_key.value
        if event.control.id == "listeners-table":
            with contextlib.suppress(ValueError):
                self._render_listener_detail(int(key))
        elif event.control.id == "connections-table" and key.startswith("h:"):
            pid = int(key[2:])
            if pid in self._conn_expanded:
                self._conn_expanded.discard(pid)
            else:
                self._conn_expanded.add(pid)
            self._render_connections_table(restore_key=key)
