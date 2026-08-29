"""Structured logging setup. Never logs sensitive values (cookies, auth headers, URLs)."""

from __future__ import annotations

import logging

from rich.console import Console
from rich.logging import RichHandler


def configure_logging(level: str = "WARNING") -> None:
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False, console=Console(stderr=True))],
        force=True,
    )
    logging.getLogger("sentinel").setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"sentinel.{name}")
