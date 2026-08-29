from __future__ import annotations

import asyncio
import importlib.metadata
import sys
from enum import StrEnum

import typer
from rich import box
from rich.console import Console
from rich.table import Table

from sentinel.config import get_config
from sentinel.log import configure_logging

app = typer.Typer(
    name="sentinel",
    help="Local security and privacy monitor.",
    no_args_is_help=False,
    invoke_without_command=True,
)
scan_app = typer.Typer(help="Run security scans.")
baseline_app = typer.Typer(help="Manage baseline expectations.")
app.add_typer(scan_app, name="scan")
app.add_typer(baseline_app, name="baseline")

console = Console()
err_console = Console(stderr=True)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    cfg = get_config()
    configure_logging(cfg.log_level)
    if ctx.invoked_subcommand is None:
        _launch_tui()


@app.command()
def version() -> None:
    """Show sentinel version."""
    try:
        v = importlib.metadata.version("sentinel")
    except importlib.metadata.PackageNotFoundError:
        v = "dev"
    console.print(f"sentinel [bold]{v}[/bold]")


@app.command()
def doctor() -> None:
    """Check environment and tool availability."""
    import platform

    table = Table(title="Environment", box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Detail")

    # Python version
    py = sys.version.split()[0]
    py_ok = tuple(int(x) for x in py.split(".")[:2]) >= (3, 12)
    _add_row(table, "Python ≥ 3.12", py_ok, py)

    # psutil
    try:
        import psutil  # noqa: F401
        import psutil as _ps

        _add_row(table, "psutil", True, _ps.__version__)
    except ImportError:
        _add_row(table, "psutil", False, "not installed")

    # rich
    try:
        import importlib.metadata as _meta

        rich_ver = _meta.version("rich")
        _add_row(table, "rich", True, rich_ver)
    except Exception:
        _add_row(table, "rich", False, "not installed")

    # textual
    try:
        import importlib.metadata as _meta2

        textual_ver = _meta2.version("textual")
        _add_row(table, "textual", True, textual_ver)
    except Exception:
        _add_row(table, "textual", False, "not installed")

    # pydantic
    try:
        import pydantic  # noqa: F401

        _add_row(table, "pydantic", True, pydantic.__version__)
    except ImportError:
        _add_row(table, "pydantic", False, "not installed")

    # osquery (optional)
    import shutil

    osq = shutil.which("osqueryi") or shutil.which("osquery")
    _add_row(table, "osquery (optional)", osq is not None, osq or "not found")

    # platform
    _add_row(table, "Platform", True, platform.platform())

    console.print(table)


def _add_row(table: Table, name: str, ok: bool, detail: str) -> None:
    status = "[green]OK[/green]" if ok else "[red]MISSING[/red]"
    table.add_row(name, status, detail)


# ── scan subcommands ────────────────────────────────────────────────────────


class ScanMode(StrEnum):
    quick = "quick"
    deep = "deep"


@scan_app.callback(invoke_without_command=True)
def scan_default(
    ctx: typer.Context,
    output_json: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
) -> None:
    """Run a quick security scan (default)."""
    if ctx.invoked_subcommand is None:
        _run_scan(output_json=output_json)


@scan_app.command("quick")
def scan_quick(
    output_json: bool = typer.Option(False, "--json", help="Machine-readable JSON output."),
) -> None:
    """Run a quick security scan."""
    _run_scan(output_json=output_json)


@scan_app.command("deep")
def scan_deep() -> None:
    """Run a deep security scan (not yet implemented)."""
    console.print("[yellow]Deep scan not yet available.[/yellow]")


def _run_scan(output_json: bool = False) -> None:
    from sentinel.application.scan_service import QuickScanService
    from sentinel.collectors.network_psutil import PsutilNetworkCollector
    from sentinel.collectors.process_psutil import PsutilProcessCollector

    svc = QuickScanService(
        process_collector=PsutilProcessCollector(),
        network_collector=PsutilNetworkCollector(),
    )

    result = asyncio.run(svc.run())

    if output_json:
        from sentinel.cli.renderers.json_renderer import render_scan_result_json

        print(render_scan_result_json(result))
    else:
        from sentinel.cli.renderers.rich_renderer import render_scan_result

        render_scan_result(result)


# ── standalone subcommands ─────────────────────────────────────────────────


@app.command()
def processes() -> None:
    """List running processes."""
    from sentinel.application.correlation import CorrelationService
    from sentinel.cli.renderers.rich_renderer import render_processes_table
    from sentinel.collectors.network_psutil import PsutilNetworkCollector
    from sentinel.collectors.process_psutil import PsutilProcessCollector

    proc_obs = asyncio.run(PsutilProcessCollector().snapshot())
    sock_obs = asyncio.run(PsutilNetworkCollector().snapshot())
    correlated = CorrelationService().correlate(proc_obs, sock_obs)
    render_processes_table(correlated)


@app.command()
def ports() -> None:
    """List listening ports."""
    from sentinel.application.correlation import CorrelationService
    from sentinel.cli.renderers.rich_renderer import render_ports_table
    from sentinel.collectors.network_psutil import PsutilNetworkCollector
    from sentinel.collectors.process_psutil import PsutilProcessCollector

    proc_obs = asyncio.run(PsutilProcessCollector().snapshot())
    sock_obs = asyncio.run(PsutilNetworkCollector().snapshot())
    correlated = CorrelationService().correlate(proc_obs, sock_obs)
    render_ports_table(correlated)


@app.command()
def network() -> None:
    """List active connections."""
    from sentinel.application.correlation import CorrelationService
    from sentinel.cli.renderers.rich_renderer import render_network_table
    from sentinel.collectors.network_psutil import PsutilNetworkCollector
    from sentinel.collectors.process_psutil import PsutilProcessCollector

    proc_obs = asyncio.run(PsutilProcessCollector().snapshot())
    sock_obs = asyncio.run(PsutilNetworkCollector().snapshot())
    correlated = CorrelationService().correlate(proc_obs, sock_obs)
    render_network_table(correlated)


@app.command()
def watch() -> None:
    """Launch the interactive TUI monitor."""
    _launch_tui()


# ── baseline subcommands ───────────────────────────────────────────────────


@baseline_app.command("list")
def baseline_list() -> None:
    """Show all baseline entries."""
    from sentinel.application.baseline_service import BaselineService
    from sentinel.storage.baseline_repository import BaselineRepository
    from sentinel.storage.database import get_engine, init_db

    engine = get_engine()
    init_db(engine)
    from sqlalchemy.orm import Session

    with Session(engine) as session:
        svc = BaselineService(BaselineRepository(session))
        entries = svc.list_all()

    if not entries:
        console.print("[dim]No baseline entries. Use 'sentinel baseline add' to add one.[/dim]")
        return

    table = Table(title="Baselines", box=box.SIMPLE_HEAD, header_style="bold cyan")
    table.add_column("ID", style="dim", width=4)
    table.add_column("Type")
    table.add_column("Subject")
    table.add_column("Reason")
    for e in entries:
        table.add_row(str(e.id), e.subject_type, e.subject, e.reason or "—")
    console.print(table)


@baseline_app.command("add")
def baseline_add(
    process: str | None = typer.Option(None, "--process", "-p", help="Process name to allow."),
    port: int | None = typer.Option(None, "--port", help="Port number to allow."),
    domain: str | None = typer.Option(None, "--domain", "-d", help="Domain to allow."),
    reason: str = typer.Option("", "--reason", "-r", help="Why this is expected."),
) -> None:
    """Add a process, port, or domain to the baseline."""
    from sqlalchemy.orm import Session

    from sentinel.application.baseline_service import BaselineService
    from sentinel.storage.baseline_repository import BaselineRepository
    from sentinel.storage.database import get_engine, init_db

    if not any([process, port, domain]):
        console.print("[red]Provide at least one of --process, --port, or --domain.[/red]")
        raise typer.Exit(1)

    engine = get_engine()
    init_db(engine)
    with Session(engine) as session:
        svc = BaselineService(BaselineRepository(session))
        if process:
            entry = svc.add_process(process, reason=reason)
            session.commit()
            console.print(f"[green]Added process baseline:[/green] {entry.subject} (id={entry.id})")
        if port is not None:
            entry = svc.add_port(port, reason=reason)
            session.commit()
            console.print(f"[green]Added port baseline:[/green] :{entry.subject} (id={entry.id})")
        if domain:
            entry = svc.add_domain(domain, reason=reason)
            session.commit()
            console.print(f"[green]Added domain baseline:[/green] {entry.subject} (id={entry.id})")


@baseline_app.command("remove")
def baseline_remove(
    entry_id: int = typer.Argument(..., help="Baseline entry ID (from 'baseline list')."),
) -> None:
    """Remove a baseline entry by ID."""
    from sqlalchemy.orm import Session

    from sentinel.application.baseline_service import BaselineService
    from sentinel.storage.baseline_repository import BaselineRepository
    from sentinel.storage.database import get_engine, init_db

    engine = get_engine()
    init_db(engine)
    with Session(engine) as session:
        svc = BaselineService(BaselineRepository(session))
        removed = svc.remove(entry_id)
        if removed:
            session.commit()
            console.print(f"[green]Removed baseline entry {entry_id}.[/green]")
        else:
            console.print(f"[red]No baseline entry with id={entry_id}.[/red]")
            raise typer.Exit(1)


def _launch_tui() -> None:
    try:
        from sentinel.tui.app import SentinelApp
    except ImportError:
        console.print(
            "[bold red]The interactive TUI requires the [cyan]textual[/cyan] package.[/bold red]\n"
            "Install it with:  [bold]pip install 'sentinel[tui]'[/bold]"
        )
        raise SystemExit(1) from None

    SentinelApp().run()
