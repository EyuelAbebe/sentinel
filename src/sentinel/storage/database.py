from __future__ import annotations

from collections.abc import Generator
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from sentinel.config import get_config


def get_db_path() -> Path:
    cfg = get_config()
    data_dir = Path(cfg.data_dir).expanduser()
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir / "sentinel.db"


def get_engine(db_path: Path | None = None) -> Engine:
    path = db_path or get_db_path()
    engine = create_engine(f"sqlite:///{path}", echo=False)
    _enable_wal(engine)
    return engine


def get_session(engine: Engine | None = None) -> Generator[Session, None, None]:
    _engine = engine or get_engine()
    factory = sessionmaker(bind=_engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _enable_wal(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_wal(dbapi_conn: Any, _: object) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


def init_db(engine: Engine | None = None) -> None:
    from sentinel.storage.models import Base

    _engine = engine or get_engine()
    Base.metadata.create_all(_engine)
