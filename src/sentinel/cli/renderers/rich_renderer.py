from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
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

_EXPOSURE_LABEL: dict[ExposureLevel, str] = {
    ExposureLevel.LOOPBACK: "[green]Localhost only[/green]",
    ExposureLevel.LOCAL_NETWORK: "[yellow]Local network[/yellow]",
    ExposureLevel.ALL_INTERFACES: "[red]All interfaces[/red]",
}


def render_scan_result(result: ScanResult) -> None:
    _render_summary(result)
    if result.findings:
        _render_attention(result.findings)
    if result.errors:
        _render_errors(result.errors)


def _render_summary(result: ScanResult) -> None:
    attention_style = "bold red" if result.attention_count > 0 else "green"
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    table.add_column("Processes", style="cyan", justify="right")
    table.add_column("Listening ports", style="cyan", justify="right")
    table.add_column("Connections", style="cyan", justify="right")
    table.add_column("Attention", style=attention_style, justify="right")
    table.add_row(
        str(result.process_count),
        str(result.listener_count),
        str(result.connection_count),
        str(result.attention_count),
    )
    console.print()
    console.print("[bold]Security Scan Complete[/bold]")
    console.print()
    console.print(table)


def _render_attention(findings: list[Finding]) -> None:
    console.print()
    for finding in findings:
        color = _SEVERITY_COLOR.get(finding.severity, "white")
        header = Text()
        header.append(f"! {finding.title}", style=f"bold {color}")
        header.append(f"  {finding.severity.upper()}", style=color)

        lines: list[str] = []
        for reason in finding.reasons:
            lines.append(f"  {reason.description}")

        body = "\n".join(lines)
        console.print(Panel(body, title=header, border_style=color, expand=False))


def _render_errors(errors: list[str]) -> None:
    console.print()
    for err in errors:
        console.print(f"[dim]Warning: {err}[/dim]")


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
    table.add_column("Ports")
    table.add_column("Path", style="dim")

    for cp in correlated:
        if cp.pid == 0:
            continue
        identity = cp.observation.identity
        ports = ", ".join(
            f":{l.local_endpoint.port}" for l in cp.listeners
        ) if cp.listeners else ""
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
    table.add_column("Port", justify="right")
    table.add_column("Protocol")
    table.add_column("Process")
    table.add_column("PID", justify="right", style="dim")
    table.add_column("Exposure")

    for cp in correlated:
        for listener in cp.listeners:
            exposure_label = _EXPOSURE_LABEL.get(listener.exposure, listener.exposure)
            table.add_row(
                str(listener.local_endpoint.port),
                listener.local_endpoint.protocol.upper(),
                cp.name,
                str(cp.pid) if cp.pid else "",
                exposure_label,
            )

    console.print(table)


def render_network_table(correlated: list[CorrelatedProcess]) -> None:
    table = Table(
        title="Active Connections",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Process")
    table.add_column("Local")
    table.add_column("Remote")
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
