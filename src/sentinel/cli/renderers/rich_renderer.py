from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from sentinel.application.correlation import CorrelatedProcess
from sentinel.application.scan_service import ScanResult
from sentinel.domain.enums import ExposureLevel, Severity
from sentinel.domain.findings import Finding

console = Console()

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.LOW: "yellow",
    Severity.MEDIUM: "dark_orange",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}

_SEVERITY_ICON: dict[Severity, str] = {
    Severity.LOW: "▲",
    Severity.MEDIUM: "◆",
    Severity.HIGH: "●",
    Severity.CRITICAL: "⬛",
}

_EXPOSURE_LABEL: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]Localhost only[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]Local network[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[bold red]⚠  All interfaces[/bold red]",
}


def render_scan_result(result: ScanResult, duration: float | None = None) -> None:
    _render_header(duration)
    _render_summary(result)
    _render_legend()
    if result.findings:
        console.print(Rule(style="dim"))
        _render_attention(result.findings)
    if result.errors:
        _render_errors(result.errors)
    _render_tip()


def _render_header(duration: float | None) -> None:
    ts = datetime.now(UTC).strftime("%H:%M:%S")
    dur_str = f"  ·  {duration:.1f}s" if duration is not None else ""
    console.print()
    console.print(
        Rule(
            f"[bold cyan]Sentinel[/bold cyan]  [dim]Quick Scan · {ts}{dur_str}[/dim]",
            style="cyan",
        )
    )


def _render_summary(result: ScanResult) -> None:
    if result.attention_count > 0:
        attn_markup = f"[bold red]{result.attention_count} ⚠[/bold red]"
        attn_style = "bold red"
    else:
        attn_markup = f"[green]{result.attention_count} ✓[/green]"
        attn_style = "green"

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Processes", style="cyan", justify="right")
    table.add_column("Ports", style="cyan", justify="right")
    table.add_column("Connections", style="cyan", justify="right")
    table.add_column("Attention", style=attn_style, justify="right")
    table.add_row(
        str(result.process_count),
        str(result.listener_count),
        str(result.connection_count),
        attn_markup,
    )
    console.print()
    console.print(table)


def _render_attention(findings: list[Finding]) -> None:
    console.print()
    for finding in findings:
        color = _SEVERITY_COLOR.get(finding.severity, "white")
        icon = _SEVERITY_ICON.get(finding.severity, "!")
        header = Text()
        header.append(f"{icon} {finding.title}", style=f"bold {color}")
        header.append(f"  {finding.severity.upper()}", style=color)

        body = Text()
        for i, reason in enumerate(finding.reasons):
            if i > 0:
                body.append("\n")
            body.append("› ", style="dim")
            body.append(reason.description)

        console.print(Panel(body, title=header, border_style=color, expand=False))


def _render_errors(errors: list[str]) -> None:
    console.print()
    for err in errors:
        console.print(f"[yellow]⚠  {err}[/yellow]")


def _render_legend() -> None:
    console.print(
        "  [dim]Severity:[/dim]"
        "  [yellow]▲ LOW[/yellow]"
        "  [dark_orange]◆ MEDIUM[/dark_orange]"
        "  [red]● HIGH[/red]"
        "  [bold red]⬛ CRITICAL[/bold red]"
        "     [dim]Attention = findings that need review[/dim]"
    )


def _render_tip() -> None:
    console.print()
    console.print(
        Rule(
            "[dim]Run [bold]sentinel watch[/bold] for live interactive monitoring[/dim]",
            style="dim",
        )
    )
    console.print()


def render_processes_table(correlated: list[CorrelatedProcess]) -> None:
    table = Table(
        title="Processes",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("PID", justify="right", style="dim", width=7)
    table.add_column("Name", style="bold")
    table.add_column("User", style="dim")
    table.add_column("Ports", style="cyan")
    table.add_column("Path", style="dim")

    for cp in correlated:
        if cp.pid == 0:
            continue
        identity = cp.observation.identity
        ports = (
            ", ".join(f":{sock.local_endpoint.port}" for sock in cp.listeners)
            if cp.listeners
            else ""
        )
        table.add_row(
            str(identity.pid),
            identity.name,
            identity.user or "",
            ports,
            identity.executable_path or "",
        )

    console.print(table)


def render_ports_table(correlated: list[CorrelatedProcess]) -> None:
    table = Table(
        title="Listening Ports",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("!", width=2)
    table.add_column("Port", justify="right", style="bold cyan")
    table.add_column("Protocol")
    table.add_column("Process")
    table.add_column("PID", justify="right", style="dim")
    table.add_column("Exposure")

    for cp in correlated:
        for listener in cp.listeners:
            exposure_label = _EXPOSURE_LABEL.get(listener.exposure, listener.exposure)
            flag = (
                "[bold red]⚠[/bold red]"
                if listener.exposure == ExposureLevel.ALL_INTERFACES
                else "[yellow]◆[/yellow]"
                if listener.exposure == ExposureLevel.LOCAL_NETWORK
                else ""
            )
            table.add_row(
                flag,
                str(listener.local_endpoint.port),
                listener.local_endpoint.protocol.upper(),
                cp.name,
                str(cp.pid) if cp.pid else "",
                exposure_label,
            )

    console.print(table)


def render_inspect(result: ScanResult, query: str) -> None:
    q = query.strip().lower()
    console.print()
    console.print(
        Rule(f"[bold cyan]Sentinel[/bold cyan]  [dim]inspect: {query}[/dim]", style="cyan")
    )
    console.print()

    matched_listeners: list[tuple[CorrelatedProcess, Any]] = []
    matched_conns: list[tuple[CorrelatedProcess, Any]] = []

    for cp in result.correlated:
        identity = cp.observation.identity
        name_lower = (identity.name or "").lower()
        path_lower = (identity.executable_path or "").lower()

        for sock in cp.listeners:
            port_str = str(sock.local_endpoint.port)
            addr_lower = (sock.local_endpoint.address or "").lower()
            if q in port_str or q in name_lower or q in addr_lower or q in path_lower:
                matched_listeners.append((cp, sock))

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
                matched_conns.append((cp, conn))

    if not matched_listeners and not matched_conns:
        console.print(f'[yellow]No results for "{query}".[/yellow]')
        console.print("[dim]Try a port number (e.g. 8080), a process name, or an IP address.[/dim]")
        console.print()
        return

    if matched_listeners:
        console.print(
            f"[bold cyan]Listening ports[/bold cyan]  ({len(matched_listeners)} match{'es' if len(matched_listeners) != 1 else ''})"
        )
        console.print()
        for cp, sock in matched_listeners:
            identity = cp.observation.identity
            exposure_label = _EXPOSURE_LABEL.get(sock.exposure, str(sock.exposure))
            flag = (
                "[bold red]⚠[/bold red]"
                if sock.exposure == ExposureLevel.ALL_INTERFACES
                else "[yellow]◆[/yellow]"
                if sock.exposure == ExposureLevel.LOCAL_NETWORK
                else "[green]·[/green]"
            )
            body = Text()
            body.append("  Process    ", style="dim")
            body.append(f"{identity.name}", style="bold")
            body.append(f"  (PID {identity.pid})\n", style="dim")
            body.append("  Address    ", style="dim")
            body.append(f"{sock.local_endpoint.address}:{sock.local_endpoint.port}  ")
            body.append(f"{sock.local_endpoint.protocol.upper()}\n", style="dim")
            body.append("  Exposure   ", style="dim")
            body.append(exposure_label)
            if identity.executable_path:
                body.append("\n  Path       ", style="dim")
                body.append(identity.executable_path, style="dim")
            if identity.user:
                body.append("\n  User       ", style="dim")
                body.append(identity.user, style="dim")
            if identity.command_line:
                cmd = " ".join(identity.command_line)[:100]
                body.append("\n  Cmd        ", style="dim")
                body.append(cmd, style="dim")
            title = Text()
            title.append(f"{flag} :{sock.local_endpoint.port}  {identity.name}", style="bold")
            console.print(Panel(body, title=title, expand=False))

    if matched_conns:
        if matched_listeners:
            console.print()
        console.print(
            f"[bold cyan]Active connections[/bold cyan]  ({len(matched_conns)} match{'es' if len(matched_conns) != 1 else ''})"
        )
        console.print()
        conn_table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
        conn_table.add_column("Process")
        conn_table.add_column("Local", style="dim")
        conn_table.add_column("Remote", style="cyan")
        conn_table.add_column("State", style="dim")
        for cp, conn in matched_conns:
            remote = ""
            if conn.remote_endpoint:
                remote = f"{conn.remote_endpoint.address}:{conn.remote_endpoint.port}"
            conn_table.add_row(
                cp.name,
                f"{conn.local_endpoint.address}:{conn.local_endpoint.port}",
                remote,
                conn.socket_state.upper(),
            )
        console.print(conn_table)

    proc_findings = [f for f in result.findings if q in f.subject.lower()]
    if proc_findings:
        console.print()
        console.print("[bold cyan]Related findings[/bold cyan]")
        console.print()
        _render_attention(proc_findings)

    console.print(Rule(style="dim"))
    console.print()


def render_network_table(correlated: list[CorrelatedProcess]) -> None:
    table = Table(
        title="Active Connections",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Process")
    table.add_column("Local", style="dim")
    table.add_column("Remote", style="cyan")
    table.add_column("State", style="dim")

    for cp in correlated:
        for conn in cp.connections:
            remote = ""
            if conn.remote_endpoint:
                remote = f"{conn.remote_endpoint.address}:{conn.remote_endpoint.port}"
            table.add_row(
                cp.name,
                f"{conn.local_endpoint.address}:{conn.local_endpoint.port}",
                remote,
                conn.socket_state.upper(),
            )

    console.print(table)
