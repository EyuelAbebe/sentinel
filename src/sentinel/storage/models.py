from __future__ import annotations

import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    """Persisted domain event — one row per process/port/connection change."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    instance_id: Mapped[str] = mapped_column(String, nullable=False, index=True)
    occurred_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    payload_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    def __repr__(self) -> str:
        return f"EventRecord(id={self.id}, type={self.event_type}, at={self.occurred_at})"


class FindingRecord(Base):
    """Persisted finding — one row per finding raised by the FindingEngine."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String, nullable=False, default="")
    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    occurred_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String, nullable=False, default="open", index=True)

    def __repr__(self) -> str:
        return f"FindingRecord(id={self.id}, title={self.title!r}, severity={self.severity})"


class BaselineEntry(Base):
    """User-defined expectation — processes/ports/domains that should not raise findings."""

    __tablename__ = "baselines"
    __table_args__ = (UniqueConstraint("subject_type", "subject", name="uq_baseline_subject"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    subject_type: Mapped[str] = mapped_column(String, nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String, nullable=False)
    reason: Mapped[str] = mapped_column(String, nullable=False, default="")
    added_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    added_by: Mapped[str] = mapped_column(String, nullable=False, default="user")

    def __repr__(self) -> str:
        return f"BaselineEntry(id={self.id}, type={self.subject_type}, subject={self.subject!r})"


class ExecutableHashRecord(Base):
    """Cached SHA-256 hash for a process executable — used for integrity change detection."""

    __tablename__ = "executable_hashes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    path: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    sha256: Mapped[str] = mapped_column(String, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mtime: Mapped[float] = mapped_column(Integer, nullable=False, default=0)
    last_seen: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    def __repr__(self) -> str:
        return f"ExecutableHashRecord(path={self.path!r}, sha256={self.sha256[:8]}...)"
