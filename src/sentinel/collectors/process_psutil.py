from __future__ import annotations

import os
from datetime import UTC, datetime

import psutil

from sentinel.domain.models import ProcessIdentity, ProcessObservation
from sentinel.log import get_logger

logger = get_logger("collectors.process")

_ATTRS = [
    "pid",
    "name",
    "exe",
    "cmdline",
    "username",
    "ppid",
    "create_time",
    "status",
]


class PsutilProcessCollector:
    async def snapshot(self) -> list[ProcessObservation]:
        now = datetime.now(UTC)
        observations: list[ProcessObservation] = []

        for proc in psutil.process_iter(_ATTRS):
            try:
                info = proc.info
                exe: str | None = info.get("exe") or None
                observations.append(
                    ProcessObservation(
                        identity=ProcessIdentity(
                            pid=info["pid"],
                            name=info.get("name") or "",
                            executable_path=exe,
                            command_line=info.get("cmdline") or [],
                            user=info.get("username"),
                            parent_pid=info.get("ppid"),
                            start_time=info.get("create_time") or 0.0,
                            executable_exists=_exe_exists(exe),
                        ),
                        observed_at=now,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as exc:
                logger.debug("Skipping process: %s", exc)

        return observations


def _exe_exists(exe: str | None) -> bool:
    if not exe:
        return True
    try:
        return os.path.exists(exe)
    except Exception:
        return True
