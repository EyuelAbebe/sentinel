from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass, field
from typing import Any

import psutil
from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable, Static

from sentinel.tui.widgets.key_bar import KeyBar


def _bar(percent: float, width: int = 32) -> str:
    filled = max(0, min(width, int(width * percent / 100)))
    empty = width - filled
    if percent >= 90:
        color = "bold red"
    elif percent >= 70:
        color = "yellow"
    else:
        color = "green"
    bar = f"[{color}]{'█' * filled}[/{color}]"
    if empty:
        bar += f"[dim]{'░' * empty}[/dim]"
    return bar


def _mini_bar(percent: float, width: int = 10) -> str:
    filled = max(0, min(width, int(width * percent / 100)))
    empty = width - filled
    if percent >= 90:
        color = "red"
    elif percent >= 70:
        color = "yellow"
    else:
        color = "green"
    bar = f"[{color}]{'█' * filled}[/{color}]"
    if empty:
        bar += f"[dim]{'░' * empty}[/dim]"
    return bar


def _fmt_bytes(n: float) -> str:
    if n < 0:
        n = 0.0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


@dataclass
class _IOState:
    disk_read: int = 0
    disk_write: int = 0
    net_sent: int = 0
    net_recv: int = 0
    ts: float = field(default_factory=time.monotonic)


class ResourcesScreen(Widget):
    DEFAULT_CSS = """
    ResourcesScreen {
        layout: vertical;
        height: 1fr;
        background: #080e18;
    }
    #metrics {
        height: auto;
        min-height: 10;
        padding: 1 2;
        background: #0d1521;
        border-bottom: solid #00ff9f;
        color: #a0c8e8;
    }
    #top-label {
        height: 1;
        padding: 0 2;
        color: #00e5ff;
        text-style: bold;
        background: #080e18;
    }
    #top-procs {
        height: 1fr;
        min-height: 5;
    }
    """

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._prev_io: _IOState | None = None
        self._primed = False

    def compose(self) -> ComposeResult:
        yield Static("[dim]Gathering system data…[/dim]", id="metrics")
        yield Static(
            "── TOP PROCESSES BY CPU ─────────────────────────────────",
            id="top-label",
        )
        table: DataTable[str] = DataTable(id="top-procs", cursor_type="row")
        table.add_columns("Name", "PID", "User", "CPU %", "Mem %", "RSS")
        yield table
        yield KeyBar(
            [
                ("↑↓", "Navigate"),
                ("s", "Rescan"),
                ("1-7", "Tabs"),
                ("?", "Help"),
                ("q", "Quit"),
            ]
        )

    def on_mount(self) -> None:
        # Prime CPU baseline — first call always returns 0.0 without this
        psutil.cpu_percent(percpu=True)
        # Poll every 2 seconds
        self.set_interval(2.0, self._schedule_update)

    def on_show(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#top-procs", DataTable).focus()
        self.run_worker(self._collect_and_render(), exclusive=True, name="res-update")

    def _schedule_update(self) -> None:
        self.run_worker(self._collect_and_render(), exclusive=True, name="res-update")

    async def _collect_and_render(self) -> None:
        # ── CPU ──────────────────────────────────────────────────────────────
        cpu_cores: list[float] = psutil.cpu_percent(percpu=True)
        cpu_total: float = sum(cpu_cores) / len(cpu_cores) if cpu_cores else 0.0

        # ── Memory ───────────────────────────────────────────────────────────
        mem = psutil.virtual_memory()

        # ── Disk / Network rates ──────────────────────────────────────────────
        now = time.monotonic()
        disk = psutil.disk_io_counters()
        net = psutil.net_io_counters()

        disk_read_rate = 0.0
        disk_write_rate = 0.0
        net_sent_rate = 0.0
        net_recv_rate = 0.0

        if self._prev_io is not None:
            dt = now - self._prev_io.ts
            if dt > 0:
                if disk is not None:
                    disk_read_rate = max(0.0, (disk.read_bytes - self._prev_io.disk_read) / dt)
                    disk_write_rate = max(0.0, (disk.write_bytes - self._prev_io.disk_write) / dt)
                if net is not None:
                    net_sent_rate = max(0.0, (net.bytes_sent - self._prev_io.net_sent) / dt)
                    net_recv_rate = max(0.0, (net.bytes_recv - self._prev_io.net_recv) / dt)

        self._prev_io = _IOState(
            disk_read=disk.read_bytes if disk is not None else 0,
            disk_write=disk.write_bytes if disk is not None else 0,
            net_sent=net.bytes_sent if net is not None else 0,
            net_recv=net.bytes_recv if net is not None else 0,
            ts=now,
        )

        # ── Top processes ─────────────────────────────────────────────────────
        top_procs: list[dict[str, Any]] = []
        attrs = ["pid", "name", "username", "cpu_percent", "memory_percent", "memory_info"]
        for proc in psutil.process_iter(attrs):
            with contextlib.suppress(
                psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess
            ):
                info = proc.info
                top_procs.append(info)

        top_by_cpu = sorted(
            top_procs,
            key=lambda p: float(p.get("cpu_percent") or 0),
            reverse=True,
        )[:20]

        # ── Render ────────────────────────────────────────────────────────────
        metrics_lines = _build_metrics_text(
            cpu_total, cpu_cores, mem, disk_read_rate, disk_write_rate, net_sent_rate, net_recv_rate
        )
        with contextlib.suppress(Exception):
            self.query_one("#metrics", Static).update("\n".join(metrics_lines))

        with contextlib.suppress(Exception):
            table = self.query_one("#top-procs", DataTable)
            table.clear()
            for p in top_by_cpu:
                mem_info = p.get("memory_info")
                rss_mb = mem_info.rss / (1024 * 1024) if mem_info is not None else 0.0
                cpu_val = float(p.get("cpu_percent") or 0)
                mem_val = float(p.get("memory_percent") or 0)
                cpu_str = (
                    f"[red]{cpu_val:.1f}[/red]"
                    if cpu_val >= 50
                    else (f"[yellow]{cpu_val:.1f}[/yellow]" if cpu_val >= 20 else f"{cpu_val:.1f}")
                )
                table.add_row(
                    (str(p.get("name") or ""))[:30],
                    str(p.get("pid") or ""),
                    (str(p.get("username") or ""))[:16],
                    cpu_str,
                    f"{mem_val:.1f}",
                    f"{rss_mb:.0f} MB",
                )


def _build_metrics_text(
    cpu_total: float,
    cpu_cores: list[float],
    mem: Any,
    disk_read: float,
    disk_write: float,
    net_sent: float,
    net_recv: float,
) -> list[str]:
    lines: list[str] = []

    # CPU overall bar
    lines.append(
        f"[bold cyan]CPU[/bold cyan]  {_bar(cpu_total, 36)}"
        f"  [bold]{cpu_total:.1f}%[/bold]"
        f"  [dim]{psutil.cpu_count(logical=False) or '?'} cores"
        f"  ({psutil.cpu_count(logical=True) or '?'} logical)[/dim]"
    )

    # Per-core bars — two per line
    cores = cpu_cores or []
    for i in range(0, len(cores), 2):
        parts: list[str] = []
        for j in range(2):
            ci = i + j
            if ci < len(cores):
                c = cores[ci]
                parts.append(f"  [dim]{ci:2d}[/dim] {_mini_bar(c, 12)} {c:4.0f}%")
        lines.append("".join(parts))

    lines.append("")

    # Memory
    mem_used_gb = mem.used / (1024**3)
    mem_total_gb = mem.total / (1024**3)
    mem_avail_gb = mem.available / (1024**3)
    lines.append(
        f"[bold cyan]RAM[/bold cyan]  {_bar(mem.percent, 36)}"
        f"  [bold]{mem.percent:.0f}%[/bold]"
        f"  [dim]{mem_used_gb:.1f} GB used  ·  {mem_avail_gb:.1f} GB free"
        f"  ·  {mem_total_gb:.1f} GB total[/dim]"
    )

    # Swap
    swap = psutil.swap_memory()
    if swap.total > 0:
        swap_used_gb = swap.used / (1024**3)
        swap_total_gb = swap.total / (1024**3)
        lines.append(
            f"[dim]Swap[/dim] {_bar(swap.percent, 36)}"
            f"  [dim]{swap.percent:.0f}%  ·  {swap_used_gb:.1f} / {swap_total_gb:.1f} GB[/dim]"
        )

    lines.append("")

    # Disk I/O
    lines.append(
        f"[bold cyan]Disk[/bold cyan] "
        f" ↓ Read  [cyan]{_fmt_bytes(disk_read)}/s[/cyan]"
        f"     ↑ Write [cyan]{_fmt_bytes(disk_write)}/s[/cyan]"
    )

    # Network I/O
    lines.append(
        f"[bold cyan]Net[/bold cyan]  "
        f" ↓ Recv  [cyan]{_fmt_bytes(net_recv)}/s[/cyan]"
        f"     ↑ Sent  [cyan]{_fmt_bytes(net_sent)}/s[/cyan]"
    )

    # GPU note (psutil doesn't expose GPU; no root-free API on macOS)
    lines.append("[dim]GPU  not available — psutil does not expose GPU metrics on macOS[/dim]")

    return lines
