from __future__ import annotations

import getpass
import json
import shutil
import subprocess
import sys
from pathlib import Path

import typer
from rich.console import Console

service_app = typer.Typer(help="Manage the Sentinel background service (macOS launchd).")

console = Console()
err_console = Console(stderr=True)

LABEL = "com.sentinel.agent"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / "com.sentinel.agent.plist"
LOG_DIR = Path.home() / "Library" / "Logs" / "sentinel"
API_URL = "http://127.0.0.1:7173"

_PLIST_TEMPLATE = """\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.sentinel.agent</string>

    <key>ProgramArguments</key>
    <array>
        <string>SENTINEL_BIN</string>
        <string>serve</string>
        <string>--host</string>
        <string>127.0.0.1</string>
        <string>--port</string>
        <string>7173</string>
    </array>

    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>

    <key>ThrottleInterval</key>
    <integer>10</integer>

    <key>StandardOutPath</key>
    <string>SENTINEL_LOG_DIR/sentinel.log</string>
    <key>StandardErrorPath</key>
    <string>SENTINEL_LOG_DIR/sentinel.err.log</string>

    <key>UserName</key>
    <string>SENTINEL_USER</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>SENTINEL_LOG_LEVEL</key>
        <string>WARNING</string>
    </dict>
</dict>
</plist>
"""


def _find_sentinel_bin() -> str | None:
    found = shutil.which("sentinel")
    if found:
        return found
    candidate = Path(sys.executable).parent / "sentinel"
    if candidate.is_file() and candidate.stat().st_mode & 0o111:
        return str(candidate)
    return None


def _launchctl(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["launchctl", *args],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        err_console.print("[red]launchctl not found — this command requires macOS.[/red]")
        raise typer.Exit(1) from None
    except subprocess.TimeoutExpired:
        err_console.print("[red]launchctl timed out.[/red]")
        raise typer.Exit(1) from None


def _is_loaded() -> bool:
    result = _launchctl("list", LABEL)
    return result.returncode == 0


@service_app.command("install")
def install() -> None:
    """Write the launchd plist and start the service at login."""
    sentinel_bin = _find_sentinel_bin()
    if not sentinel_bin:
        err_console.print(
            "[red]Cannot find the sentinel binary.[/red]\n"
            "Make sure sentinel is installed and on your PATH, then retry."
        )
        raise typer.Exit(1)

    PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    plist = (
        _PLIST_TEMPLATE.replace("SENTINEL_BIN", sentinel_bin)
        .replace("SENTINEL_LOG_DIR", str(LOG_DIR))
        .replace("SENTINEL_USER", getpass.getuser())
    )
    PLIST_PATH.write_text(plist)
    console.print(f"  Wrote plist  [dim]{PLIST_PATH}[/dim]")

    if _is_loaded():
        _launchctl("unload", str(PLIST_PATH))

    result = _launchctl("load", str(PLIST_PATH))
    if result.returncode != 0:
        err_console.print(f"[red]launchctl load failed:[/red] {result.stderr.strip()}")
        raise typer.Exit(1)

    console.print("[green]Sentinel service installed and started.[/green]")
    console.print(f"  Logs  [dim]{LOG_DIR}/sentinel.log[/dim]")
    console.print(f"  API   [dim]{API_URL}/health[/dim]")
    console.print("  Check status with:  [bold]sentinel service status[/bold]")


@service_app.command("uninstall")
def uninstall() -> None:
    """Stop the service and remove the launchd plist."""
    if _is_loaded():
        _launchctl("unload", str(PLIST_PATH))
        console.print("  Stopped service.")

    if PLIST_PATH.exists():
        PLIST_PATH.unlink()
        console.print(f"  Removed  [dim]{PLIST_PATH}[/dim]")
    else:
        console.print("[dim]Plist not found — nothing to remove.[/dim]")

    console.print("[green]Sentinel service uninstalled.[/green]")


@service_app.command("start")
def start() -> None:
    """Start the service (must be installed first)."""
    if not PLIST_PATH.exists():
        err_console.print(
            "[red]Service is not installed.[/red]\n"
            "Run  [bold]sentinel service install[/bold]  first."
        )
        raise typer.Exit(1)

    if _is_loaded():
        console.print("[dim]Service is already running.[/dim]")
        return

    result = _launchctl("load", str(PLIST_PATH))
    if result.returncode != 0:
        err_console.print(f"[red]Failed to start:[/red] {result.stderr.strip()}")
        raise typer.Exit(1)

    console.print("[green]Sentinel service started.[/green]")


@service_app.command("stop")
def stop() -> None:
    """Stop the running service."""
    if not _is_loaded():
        console.print("[dim]Service is not running.[/dim]")
        return

    result = _launchctl("unload", str(PLIST_PATH))
    if result.returncode != 0:
        err_console.print(f"[red]Failed to stop:[/red] {result.stderr.strip()}")
        raise typer.Exit(1)

    console.print("[green]Sentinel service stopped.[/green]")


@service_app.command("restart")
def restart() -> None:
    """Restart the service."""
    if not PLIST_PATH.exists():
        err_console.print(
            "[red]Service is not installed.[/red]\n"
            "Run  [bold]sentinel service install[/bold]  first."
        )
        raise typer.Exit(1)

    if _is_loaded():
        _launchctl("unload", str(PLIST_PATH))
        console.print("  Stopped.")

    result = _launchctl("load", str(PLIST_PATH))
    if result.returncode != 0:
        err_console.print(f"[red]Failed to start:[/red] {result.stderr.strip()}")
        raise typer.Exit(1)

    console.print("[green]Sentinel service restarted.[/green]")


@service_app.command("status")
def status() -> None:
    """Show whether the service is running and check the API health."""
    installed = PLIST_PATH.exists()
    loaded = installed and _is_loaded()

    pid: int | None = None
    if loaded:
        r = _launchctl("list", LABEL)
        try:
            data = json.loads(r.stdout)
            pid = data.get("PID")
        except (json.JSONDecodeError, AttributeError):
            pass

    install_line = "[green]installed[/green]" if installed else "[red]not installed[/red]"
    run_line = (
        f"[green]running[/green]  [dim](PID {pid})[/dim]"
        if pid
        else ("[yellow]loaded but not yet running[/yellow]" if loaded else "[red]stopped[/red]")
    )

    console.print(f"  Install  {install_line}")
    console.print(f"  Service  {run_line}")

    # API health probe
    try:
        import urllib.error
        import urllib.request

        req = urllib.request.urlopen(f"{API_URL}/health", timeout=2)
        body = req.read().decode()
        console.print(f"  API      [green]reachable[/green]  [dim]{body.strip()[:60]}[/dim]")
    except Exception:
        console.print(f"  API      [dim]not reachable at {API_URL}/health[/dim]")

    console.print(f"  Logs     [dim]{LOG_DIR}/sentinel.log[/dim]")

    if not installed:
        console.print("\n  Run  [bold]sentinel service install[/bold]  to set up the service.")
