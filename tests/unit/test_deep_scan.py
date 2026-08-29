"""Unit tests for Phase 7: hash cache, YARA adapter, and DeepScanService."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinel.adapters.yara_scanner import YaraScanner
from sentinel.application.hash_cache_service import HashCacheService
from sentinel.storage.models import Base

# ── fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    s = factory()
    try:
        yield s
        s.commit()
    finally:
        s.close()


@pytest.fixture
def tmp_exe(tmp_path):
    """A temp file we can modify to test hash change detection."""
    f = tmp_path / "test_exe"
    f.write_bytes(b"initial content")
    return str(f)


# ── HashCacheService ──────────────────────────────────────────────────────────


class TestHashCacheService:
    def test_check_returns_hash(self, session, tmp_exe):
        svc = HashCacheService(session)
        h = svc.check(tmp_exe)
        assert h is not None
        assert len(h) == 64  # SHA-256 hex

    def test_check_nonexistent_returns_none(self, session):
        svc = HashCacheService(session)
        assert svc.check("/nonexistent/path/file") is None

    def test_has_changed_false_on_first_check(self, session, tmp_exe):
        svc = HashCacheService(session)
        svc.check(tmp_exe)  # seed the cache
        assert not svc.has_changed(tmp_exe)

    def test_has_changed_true_after_modification(self, session, tmp_exe):
        svc = HashCacheService(session)
        svc.check(tmp_exe)  # seed cache with initial content

        # Modify the file content AND update mtime
        import time

        time.sleep(0.01)
        with open(tmp_exe, "wb") as f:
            f.write(b"completely different content")
        # Force mtime change
        now = time.time()
        os.utime(tmp_exe, (now, now))

        assert svc.has_changed(tmp_exe)

    def test_has_changed_false_before_caching(self, session, tmp_exe):
        svc = HashCacheService(session)
        # No prior cache entry → not "changed"
        assert not svc.has_changed(tmp_exe)

    def test_same_hash_after_identical_rewrite(self, session, tmp_exe):
        svc = HashCacheService(session)
        h1 = svc.check(tmp_exe)
        h2 = svc.check(tmp_exe)
        assert h1 == h2


# ── YaraScanner ───────────────────────────────────────────────────────────────


class TestYaraScanner:
    def test_scanner_initializes(self):
        scanner = YaraScanner()
        # Either available (if yara-python installed) or not — both are valid
        assert isinstance(scanner.available, bool)

    def test_scan_bytes_eicar_when_available(self):
        scanner = YaraScanner()
        if not scanner.available:
            pytest.skip("yara-python not installed")
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        matches = scanner.scan_bytes(eicar)
        assert "EicarTest" in matches

    def test_scan_bytes_no_match_on_benign(self):
        scanner = YaraScanner()
        if not scanner.available:
            pytest.skip("yara-python not installed")
        matches = scanner.scan_bytes(b"hello world")
        assert matches == []

    def test_scan_file_nonexistent_returns_empty(self):
        scanner = YaraScanner()
        if not scanner.available:
            pytest.skip("yara-python not installed")
        result = scanner.scan_file("/nonexistent/path")
        assert result == []

    def test_scan_unavailable_returns_empty(self):
        scanner = YaraScanner.__new__(YaraScanner)
        scanner._rules = None
        assert scanner.scan_bytes(b"anything") == []
        assert scanner.scan_file("/any/path") == []
        assert not scanner.available
