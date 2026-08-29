"""ExecutableHashCacheService — SHA-256 integrity tracking for process binaries.

On each check, the file's mtime is compared to the cached value. If mtime is
unchanged the cached hash is returned without re-reading the file. If mtime
changed, the file is re-hashed and the record updated. A return value of True
from `has_changed` indicates the hash differs from the last recorded value.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.orm import Session

from sentinel.log import get_logger
from sentinel.storage.models import ExecutableHashRecord

logger = get_logger("hash_cache")

_CHUNK = 65_536  # 64 KB read chunks


def _sha256(path: str) -> tuple[str, int, float] | None:
    """Compute SHA-256 of a file. Returns (hex, size_bytes, mtime) or None on error."""
    try:
        p = Path(path)
        stat = p.stat()
        digest = hashlib.sha256()
        with p.open("rb") as fh:
            while chunk := fh.read(_CHUNK):
                digest.update(chunk)
        return digest.hexdigest(), stat.st_size, stat.st_mtime
    except (OSError, PermissionError) as exc:
        logger.debug("cannot hash %s: %s", path, exc)
        return None


class HashCacheService:
    """Checks and caches executable hashes; detects integrity changes."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def check(self, path: str) -> str | None:
        """Return current SHA-256 for path, updating cache if needed.

        Returns None when the file is inaccessible.
        """
        result = _sha256(path)
        if result is None:
            return None
        hex_hash, size, mtime = result
        from sqlalchemy import select

        record = self._session.scalar(
            select(ExecutableHashRecord).where(ExecutableHashRecord.path == path)
        )
        if record is None:
            record = ExecutableHashRecord(
                path=path,
                sha256=hex_hash,
                size_bytes=size,
                mtime=mtime,
                last_seen=datetime.now(UTC),
            )
            self._session.add(record)
        elif record.mtime != mtime:
            record.sha256 = hex_hash
            record.size_bytes = size
            record.mtime = mtime
            record.last_seen = datetime.now(UTC)
        else:
            record.last_seen = datetime.now(UTC)
        self._session.flush()
        return hex_hash

    def has_changed(self, path: str) -> bool:
        """Return True if the executable at path has a different hash than cached."""
        from sqlalchemy import select

        record = self._session.scalar(
            select(ExecutableHashRecord).where(ExecutableHashRecord.path == path)
        )
        if record is None:
            return False

        try:
            p = Path(path)
            stat = p.stat()
        except OSError:
            return False

        if record.mtime == stat.st_mtime:
            return False

        result = _sha256(path)
        if result is None:
            return False
        new_hash, size, mtime = result
        changed = new_hash != record.sha256
        if changed:
            record.sha256 = new_hash
            record.size_bytes = size
            record.mtime = mtime
            record.last_seen = datetime.now(UTC)
            self._session.flush()
        return changed
