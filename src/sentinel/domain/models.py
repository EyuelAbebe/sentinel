from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, Field, computed_field

from sentinel.domain.enums import (
    ExposureLevel,
    IdentityStatus,
    PrivacyCategory,
    Protocol,
    SocketState,
)


def _make_instance_id(pid: int, start_time: float) -> str:
    """Stable process instance ID that survives PID reuse."""
    return str(uuid.uuid5(uuid.NAMESPACE_OID, f"{pid}:{start_time:.3f}"))


class ProcessIdentity(BaseModel):
    pid: int
    name: str
    executable_path: str | None = None
    command_line: list[str] = Field(default_factory=list)
    user: str | None = None
    parent_pid: int | None = None
    start_time: float
    executable_exists: bool = True
    code_signature_status: str | None = None
    content_hash: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def instance_id(self) -> str:
        return _make_instance_id(self.pid, self.start_time)

    @property
    def exe_path(self) -> Path | None:
        return Path(self.executable_path) if self.executable_path else None

    def is_in_suspicious_location(self) -> bool:
        if not self.executable_path:
            return False
        p = self.executable_path.lower()
        return any(
            segment in p for segment in ["/downloads/", "/tmp/", "/var/tmp/", "/private/tmp/"]
        )


class ProcessObservation(BaseModel):
    identity: ProcessIdentity
    observed_at: datetime = Field(default_factory=datetime.utcnow)


class NetworkEndpoint(BaseModel):
    address: str
    port: int
    protocol: Protocol = Protocol.TCP
    hostname: str | None = None
    organization: str | None = None
    category: PrivacyCategory | None = None
    known_status: IdentityStatus = IdentityStatus.UNKNOWN
    reputation: str | None = None


class SocketObservation(BaseModel):
    process_instance_id: str | None = None
    pid: int | None = None
    local_endpoint: NetworkEndpoint
    remote_endpoint: NetworkEndpoint | None = None
    socket_state: SocketState = SocketState.UNKNOWN
    listening: bool = False
    exposure: ExposureLevel = ExposureLevel.LOOPBACK
    observed_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def socket_key(self) -> str:
        """Stable key for deduplication across snapshots."""
        local = f"{self.local_endpoint.address}:{self.local_endpoint.port}/{self.local_endpoint.protocol}"
        remote = ""
        if self.remote_endpoint:
            remote = f"->{self.remote_endpoint.address}:{self.remote_endpoint.port}"
        pid_part = f"pid={self.pid}" if self.pid else ""
        return f"{pid_part}:{local}{remote}"
