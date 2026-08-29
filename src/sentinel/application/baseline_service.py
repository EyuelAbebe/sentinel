"""BaselineService — manages user-defined expectations that suppress findings."""

from __future__ import annotations

from sentinel.storage.baseline_repository import BaselineRepository
from sentinel.storage.models import BaselineEntry


class BaselineService:
    """Thin service layer over BaselineRepository.

    All write operations must be called within a session context managed by
    the caller.  Read operations are used by FindingEngine at scan time.
    """

    def __init__(self, repository: BaselineRepository) -> None:
        self._repo = repository

    # ── read ──────────────────────────────────────────────────────────────────

    def is_process_expected(self, name: str) -> bool:
        return self._repo.find_by_subject("process", name) is not None

    def is_port_expected(self, port: int) -> bool:
        return self._repo.find_by_subject("port", str(port)) is not None

    def is_domain_expected(self, domain: str) -> bool:
        return self._repo.find_by_subject("domain", domain) is not None

    def list_all(self) -> list[BaselineEntry]:
        return self._repo.query_all()

    # ── write ─────────────────────────────────────────────────────────────────

    def add_process(self, name: str, reason: str = "") -> BaselineEntry:
        return self._repo.write("process", name, reason=reason)

    def add_port(self, port: int, reason: str = "") -> BaselineEntry:
        return self._repo.write("port", str(port), reason=reason)

    def add_domain(self, domain: str, reason: str = "") -> BaselineEntry:
        return self._repo.write("domain", domain, reason=reason)

    def remove(self, entry_id: int) -> bool:
        return self._repo.delete(entry_id)
