from __future__ import annotations

import contextlib
import ipaddress
from typing import Any

from textual.app import ComposeResult
from textual.events import Key
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel, Severity
from sentinel.domain.findings import Finding
from sentinel.tui.widgets.key_bar import KeyBar

_SEV_FLAG: dict[Severity, str] = {
    Severity.CRITICAL: "[bold red]⬛[/bold red]",
    Severity.HIGH: "[red]●[/red]",
    Severity.MEDIUM: "[dark_orange]◆[/dark_orange]",
    Severity.LOW: "[yellow]▲[/yellow]",
}

_SEV_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "dark_orange",
    Severity.LOW: "yellow",
}

_SEV_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_EXPOSURE_SHORT: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]loop[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]local[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]all ⚠[/bold red]",
}

_SUSPICIOUS_PATH_FRAGMENTS = ("/tmp/", "/var/tmp/", "/Downloads/", "/Temp/")


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


def _status_badge(
    cp: CorrelatedProcess, finding: Finding | None, suspicious_path: bool
) -> tuple[str, str]:
    """Return (flag markup, status markup) for a process row."""
    if finding:
        flag = _SEV_FLAG.get(finding.severity, "[yellow]![/yellow]")
        color = _SEV_COLOR.get(finding.severity, "red")
        return flag, f"[{color}]FLAGGED[/{color}]"
    if suspicious_path:
        return "[yellow]▲[/yellow]", "[yellow]SUSPECT[/yellow]"
    if cp.listeners:
        return "[green]✓[/green]", "[green]LISTENING[/green]"
    return "", "[dim]CLEAN[/dim]"


class AppsScreen(Widget):
    DEFAULT_CSS = """
    AppsScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #process-table {
        height: 1fr;
    }
    #detail-panel {
        height: 11;
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
        self._expanded: set[str] = set()
        self._current_key: str | None = None

    def compose(self) -> ComposeResult:
        table: DataTable[str] = DataTable(id="process-table", cursor_type="row")
        table.add_columns("!", "PID", "Name", "User", "Ports", "Conns", "Status", "Path")
        yield table
        yield Static(
            "[dim]↑ ↓  navigate  ·  →  expand connections  ·  ←  collapse  ·  Enter  toggle[/dim]",
            id="detail-panel",
        )
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("→←", "Expand"),
                ("s", "Rescan"),
                ("p", "Pause"),
                ("1-7", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def on_show(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#process-table", DataTable).focus()

    def on_key(self, event: Key) -> None:
        focused = self.app.focused
        if not isinstance(focused, DataTable) or focused.id != "process-table":
            return
        if event.key not in ("right", "left"):
            return
        key = self._current_key
        if not key:
            return
        if key.startswith("p:"):
            iid = key[2:]
            if event.key == "right":
                cp = next((c for c in self._correlated if c.instance_id == iid), None)
                if cp and cp.connections:
                    self._expanded.add(iid)
                    self._render_table(restore_key=key)
            else:
                self._expanded.discard(iid)
                self._render_table(restore_key=key)
            event.stop()
        elif key.startswith("c:") and event.key == "left":
            iid = key.split(":")[1]
            self._expanded.discard(iid)
            self._render_table(restore_key=f"p:{iid}")
            event.stop()

    def update_result(self, result: ScanResult) -> None:
        self._correlated = result.correlated
        self._findings = result.findings
        self._render_table()

    def _render_table(self, restore_key: str | None = None) -> None:
        flagged: dict[str, Finding] = {}
        for f in self._findings:
            existing = flagged.get(f.subject)
            if existing is None or _SEV_ORDER.get(f.severity, 0) > _SEV_ORDER.get(
                existing.severity, 0
            ):
                flagged[f.subject] = f

        table = self.query_one("#process-table", DataTable)
        saved = restore_key or self._current_key
        table.clear()

        for cp in self._correlated:
            if cp.pid == 0:
                continue
            identity = cp.observation.identity
            iid = identity.instance_id
            ports = ", ".join(f":{sock.local_endpoint.port}" for sock in cp.listeners)
            conns_count = len(cp.connections)
            is_exp = iid in self._expanded
            has_conns = conns_count > 0

            suspicious_path = any(
                p in (identity.executable_path or "") for p in _SUSPICIOUS_PATH_FRAGMENTS
            )
            finding = flagged.get(identity.name)
            flag, status = _status_badge(cp, finding, suspicious_path)

            path_short = identity.executable_path or ""
            if "/Applications/" in path_short:
                parts = path_short.split("/Applications/", 1)
                path_short = parts[1]
            elif "/Library/" in path_short:
                path_short = "…/" + path_short.rsplit("/", 2)[-1]

            if has_conns:
                arrow = "[bold cyan]▼[/bold cyan]" if is_exp else "[dim]▶[/dim]"
                conn_str = f"{arrow} [cyan]{conns_count}[/cyan]"
            else:
                conn_str = "[dim]0[/dim]"

            table.add_row(
                flag,
                str(identity.pid),
                identity.name,
                identity.user or "",
                ports,
                conn_str,
                status,
                path_short,
                key=f"p:{iid}",
            )

            if is_exp:
                for i, conn in enumerate(cp.connections):
                    remote_addr = conn.remote_endpoint.address if conn.remote_endpoint else None
                    remote_port = conn.remote_endpoint.port if conn.remote_endpoint else None
                    remote_str = f"{remote_addr}:{remote_port}" if remote_addr else "—"
                    conn_type = _classify_remote(remote_addr)
                    table.add_row(
                        "",
                        "",
                        f"  [dim]└[/dim] [dim]{remote_str}[/dim]",
                        "",
                        f"[dim]{conn.local_endpoint.address}:{conn.local_endpoint.port}[/dim]",
                        conn_type,
                        conn.socket_state.upper(),
                        "",
                        key=f"c:{iid}:{i}",
                    )

        if saved:
            fallback = f"p:{saved.split(':')[1]}" if saved.startswith("c:") else None
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

    def _render_detail(self, row_key_value: str | None) -> None:
        if not row_key_value:
            return
        if row_key_value.startswith("p:"):
            self._render_process_detail(row_key_value[2:])
        elif row_key_value.startswith("c:"):
            parts = row_key_value.split(":")
            self._render_conn_detail(parts[1], int(parts[2]))

    def _render_process_detail(self, iid: str) -> None:
        cp = next((c for c in self._correlated if c.instance_id == iid), None)
        if not cp:
            return
        identity = cp.observation.identity
        proc_findings = [f for f in self._findings if f.subject == identity.name]
        is_exp = iid in self._expanded

        lines: list[str] = [
            f"[bold]{identity.name}[/bold]"
            f"  [dim]PID {identity.pid}[/dim]"
            f"  [dim]·[/dim]  [dim]User:[/dim] {identity.user or '(unknown)'}"
            f"  [dim]·[/dim]  [dim]PPID:[/dim] {identity.parent_pid or '—'}",
        ]

        if proc_findings:
            lines.append("")
            for finding in proc_findings:
                color = _SEV_COLOR.get(finding.severity, "red")
                flag = _SEV_FLAG.get(finding.severity, "!")
                lines.append(f"  {flag} [{color}]{finding.title}[/{color}]")
                for r in finding.reasons[:2]:
                    lines.append(f"    [dim]› {r.description}[/dim]")

        if cp.listeners:
            lines.append("")
            for sock in cp.listeners:
                exposure = _EXPOSURE_SHORT.get(sock.exposure, str(sock.exposure))
                lines.append(
                    f"  [dim]LISTEN[/dim]  :{sock.local_endpoint.port}"
                    f"  {sock.local_endpoint.protocol.upper()}"
                    f"  {exposure}"
                    f"  [dim]{sock.local_endpoint.address}[/dim]"
                )

        if cp.connections:
            n = len(cp.connections)
            hint = (
                "[bold]←[/bold] collapse"
                if is_exp
                else "[bold]→[/bold] expand  ·  [bold]Enter[/bold] toggle"
            )
            lines.append(f"\n  [dim]{n} connection{'s' if n != 1 else ''}  ·  {hint}[/dim]")

        lines.append("")
        lines.append(f"  [dim]Path[/dim]  {identity.executable_path or '(unknown)'}")
        if identity.command_line:
            cmd = " ".join(identity.command_line)[:140]
            lines.append(f"  [dim]Cmd[/dim]   {cmd}")

        with contextlib.suppress(Exception):
            self.query_one("#detail-panel", Static).update("\n".join(lines))

    def _render_conn_detail(self, iid: str, idx: int) -> None:
        cp = next((c for c in self._correlated if c.instance_id == iid), None)
        if not cp or idx >= len(cp.connections):
            return
        conn = cp.connections[idx]
        identity = cp.observation.identity
        remote_addr = conn.remote_endpoint.address if conn.remote_endpoint else None
        remote_port = conn.remote_endpoint.port if conn.remote_endpoint else None
        remote_str = f"{remote_addr}:{remote_port}" if remote_addr else "—"
        conn_type = _classify_remote(remote_addr)

        lines = [
            f"[bold]{identity.name}[/bold]  [dim](PID {identity.pid})[/dim]"
            f"  ·  {conn.socket_state.upper()}  ·  {conn_type}",
            f"  [dim]Local[/dim]   {conn.local_endpoint.address}:{conn.local_endpoint.port}",
            f"  [dim]Remote[/dim]  {remote_str}",
            f"  [dim]Proto[/dim]   {conn.local_endpoint.protocol.upper()}",
        ]
        if identity.executable_path:
            lines.append(f"  [dim]Path[/dim]    {identity.executable_path}")
        lines.append("\n  [dim][bold]←[/bold] collapse to process[/dim]")

        with contextlib.suppress(Exception):
            self.query_one("#detail-panel", Static).update("\n".join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and event.row_key.value is not None:
            self._current_key = event.row_key.value
            self._render_detail(event.row_key.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if not event.row_key or event.row_key.value is None:
            return
        key = event.row_key.value
        if key.startswith("p:"):
            iid = key[2:]
            cp = next((c for c in self._correlated if c.instance_id == iid), None)
            if cp and cp.connections:
                if iid in self._expanded:
                    self._expanded.discard(iid)
                else:
                    self._expanded.add(iid)
                self._render_table(restore_key=key)
        else:
            self._render_detail(key)
