from __future__ import annotations

import contextlib
from typing import Any

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Input, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel
from sentinel.tui.widgets.key_bar import KeyBar

_EXPOSURE_LABEL: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]Localhost only[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]Local network[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]All interfaces ⚠[/bold red]",
}


class SearchScreen(Widget):
    DEFAULT_CSS = """
    SearchScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #search-input {
        height: 3;
        border: solid #00e5ff;
        background: #0d1521;
        color: #00ff9f;
        padding: 0 2;
        margin: 1 2 0 2;
    }
    #search-input:focus {
        border: solid #00ff9f;
    }
    #search-hint {
        height: 1;
        padding: 0 4;
        color: #2a6a8a;
    }
    #results-table {
        height: 1fr;
        min-height: 5;
    }
    #search-detail {
        height: 10;
        border-top: solid #00ff9f;
        padding: 1 2;
        background: #0d1521;
        color: #a0c8e8;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._correlated: list[CorrelatedProcess] = []
        self._result_rows: list[dict[str, Any]] = []

    def compose(self) -> ComposeResult:
        yield Input(
            placeholder="Search by port number, process name, or IP address…",
            id="search-input",
        )
        yield Static(
            "[dim]Examples:  8080  ·  nginx  ·  192.168.1.1  ·  chrome[/dim]",
            id="search-hint",
        )
        table: DataTable[str] = DataTable(id="results-table", cursor_type="row")
        table.add_columns("Type", "Port / Address", "Process", "State / Exposure")
        yield table
        yield Static(
            "[dim]Type to filter  ·  ↑ ↓  navigate  ·  Tab  switch to table[/dim]",
            id="search-detail",
        )
        yield KeyBar(
            [
                ("/", "Search"),
                ("↑↓", "Navigate"),
                ("Tab", "Table"),
                ("s", "Rescan"),
                ("1-7", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def on_show(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#search-input", Input).focus()

    def focus_input(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#search-input", Input).focus()

    def update_result(self, result: ScanResult) -> None:
        self._correlated = result.correlated
        with contextlib.suppress(Exception):
            query = self.query_one("#search-input", Input).value
            self._run_query(query)

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self._run_query(event.value)

    def _run_query(self, query: str) -> None:
        table = self.query_one("#results-table", DataTable)
        table.clear()
        self._result_rows = []

        q = query.strip().lower()
        if not q:
            with contextlib.suppress(Exception):
                self.query_one("#search-detail", Static).update(
                    "[dim]Type to filter  ·  ↑ ↓  navigate  ·  Tab  switch to table[/dim]"
                )
            return

        for cp in self._correlated:
            identity = cp.observation.identity
            name_lower = (identity.name or "").lower()
            path_lower = (identity.executable_path or "").lower()

            for sock in cp.listeners:
                port_str = str(sock.local_endpoint.port)
                addr_lower = (sock.local_endpoint.address or "").lower()
                if q in port_str or q in name_lower or q in addr_lower or q in path_lower:
                    row: dict[str, Any] = {
                        "kind": "listener",
                        "cp": cp,
                        "sock": sock,
                    }
                    idx = len(self._result_rows)
                    self._result_rows.append(row)
                    table.add_row(
                        "[cyan]LISTEN[/cyan]",
                        f":{sock.local_endpoint.port}",
                        identity.name,
                        _EXPOSURE_LABEL.get(sock.exposure, str(sock.exposure)),
                        key=str(idx),
                    )

            for conn in cp.connections:
                local_str = f"{conn.local_endpoint.address}:{conn.local_endpoint.port}"
                remote_str = ""
                if conn.remote_endpoint:
                    remote_str = f"{conn.remote_endpoint.address}:{conn.remote_endpoint.port}"
                if (
                    q in local_str.lower()
                    or q in remote_str.lower()
                    or q in name_lower
                    or q in path_lower
                ):
                    row = {
                        "kind": "connection",
                        "cp": cp,
                        "conn": conn,
                        "remote_str": remote_str,
                    }
                    idx = len(self._result_rows)
                    self._result_rows.append(row)
                    table.add_row(
                        "[dim]CONN[/dim]",
                        remote_str or local_str,
                        identity.name,
                        conn.socket_state.upper(),
                        key=str(idx),
                    )

        n = len(self._result_rows)
        if n > 0:
            hint = (
                f"[dim]{n} result{'s' if n != 1 else ''} for "
                f"[bold]{query.strip()}[/bold] — ↑ ↓ navigate  ·  Tab focus table[/dim]"
            )
        else:
            hint = f'[yellow]No results for "{query.strip()}"[/yellow]'
        with contextlib.suppress(Exception):
            self.query_one("#search-detail", Static).update(hint)

    def _render_detail(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._result_rows):
            return
        row = self._result_rows[idx]
        cp: CorrelatedProcess = row["cp"]
        identity = cp.observation.identity
        lines: list[str] = []

        if row["kind"] == "listener":
            sock = row["sock"]
            exposure_label = _EXPOSURE_LABEL.get(sock.exposure, str(sock.exposure))
            lines = [
                f"[bold]Listener  :{sock.local_endpoint.port}[/bold]"
                f"  [dim]{sock.local_endpoint.protocol.upper()}[/dim]",
                "",
                f"  [dim]Process[/dim]       [bold]{identity.name}[/bold]"
                f"  [dim](PID {identity.pid})[/dim]",
                f"  [dim]Bind address[/dim]  {sock.local_endpoint.address}",
                f"  [dim]Exposure[/dim]      {exposure_label}",
            ]
            if identity.executable_path:
                lines.append(f"  [dim]Path[/dim]          {identity.executable_path}")
            if identity.user:
                lines.append(f"  [dim]User[/dim]          {identity.user}")
            if identity.command_line:
                cmd = " ".join(identity.command_line)[:120]
                lines.append(f"  [dim]Cmd[/dim]           {cmd}")
        else:
            conn = row["conn"]
            remote = row.get("remote_str") or "—"
            lines = [
                f"[bold]Connection[/bold]  [dim]{conn.socket_state.upper()}[/dim]",
                "",
                f"  [dim]Process[/dim]  [bold]{identity.name}[/bold]"
                f"  [dim](PID {identity.pid})[/dim]",
                f"  [dim]Local[/dim]    {conn.local_endpoint.address}:{conn.local_endpoint.port}",
                f"  [dim]Remote[/dim]   {remote}",
                f"  [dim]Proto[/dim]    {conn.local_endpoint.protocol.upper()}",
            ]
            if identity.executable_path:
                lines.append(f"  [dim]Path[/dim]     {identity.executable_path}")
            if identity.user:
                lines.append(f"  [dim]User[/dim]     {identity.user}")

        with contextlib.suppress(Exception):
            self.query_one("#search-detail", Static).update("\n".join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        self._render_detail(int(event.row_key.value))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        self._render_detail(int(event.row_key.value))
