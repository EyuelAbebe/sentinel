"""FastAPI application — local HTTP/WebSocket API for Sentinel.

Start with: sentinel serve [--port 7173]

Endpoints:
  GET  /                     — browser dashboard (live UI)
  GET  /health               — liveness probe
  GET  /classify?domain=...  — classify a domain name
  GET  /scan                 — run a quick scan and return results
  GET  /findings             — return most recent findings from SQLite
  GET  /baseline             — list baseline entries
  WS   /events               — stream live domain events from EventBus
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from sentinel.application.classification_service import ClassificationService
from sentinel.application.event_bus import EventBus
from sentinel.application.scan_service import QuickScanService
from sentinel.collectors.network_psutil import PsutilNetworkCollector
from sentinel.collectors.process_psutil import PsutilProcessCollector
from sentinel.domain.events import Event as DomainEvent
from sentinel.log import get_logger

logger = get_logger("api")

_DASHBOARD_HTML = (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")

# ── application state ─────────────────────────────────────────────────────────

_bus = EventBus()
_classifier = ClassificationService()
_scan_svc = QuickScanService(
    process_collector=PsutilProcessCollector(),
    network_collector=PsutilNetworkCollector(),
)

# WebSocket clients subscribed to the event stream
_ws_clients: list[WebSocket] = []


async def _broadcast_event(event: DomainEvent) -> None:
    if not _ws_clients:
        return
    payload = {
        "event_type": event.event_type.value,
        "timestamp": event.timestamp.isoformat(),
        "payload": event.payload,
    }
    dead: list[WebSocket] = []
    for ws in list(_ws_clients):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _ws_clients.remove(ws)


_bus.subscribe_all(_broadcast_event)

# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Sentinel",
    description="Local security and privacy monitoring API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ── routes ────────────────────────────────────────────────────────────────────


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def dashboard() -> HTMLResponse:
    return HTMLResponse(content=_DASHBOARD_HTML)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "time": datetime.now(UTC).isoformat()}


@app.get("/classify")
async def classify(domain: str = Query(..., min_length=1)) -> dict[str, Any]:
    ev = _classifier.classify(domain)
    return {
        "domain": domain,
        "organization": ev.organization,
        "category": ev.category,
        "identity_status": ev.identity_status,
        "confidence": ev.confidence,
        "source": ev.source,
        "source_version": ev.source_version,
    }


@app.get("/scan")
async def scan() -> dict[str, Any]:
    try:
        result = await _scan_svc.run()
    except Exception as exc:
        logger.error("scan failed: %s", exc)
        return {"error": str(exc)}

    listeners = []
    connections = []
    processes = []
    seen_pids: set[int] = set()

    for cp in result.correlated:
        for sock in cp.listeners:
            listeners.append(
                {
                    "port": sock.local_endpoint.port,
                    "protocol": sock.local_endpoint.protocol.upper(),
                    "address": sock.local_endpoint.address,
                    "exposure": sock.exposure.value,
                    "process": cp.name,
                    "pid": cp.pid,
                }
            )
        for conn in cp.connections:
            remote = None
            if conn.remote_endpoint:
                remote = {
                    "address": conn.remote_endpoint.address,
                    "port": conn.remote_endpoint.port,
                }
            connections.append(
                {
                    "process": cp.name,
                    "pid": cp.pid,
                    "local_address": conn.local_endpoint.address,
                    "local_port": conn.local_endpoint.port,
                    "remote": remote,
                    "state": conn.socket_state.upper(),
                    "protocol": conn.local_endpoint.protocol.upper(),
                }
            )
        if cp.pid not in seen_pids:
            seen_pids.add(cp.pid)
            identity = cp.observation.identity
            port_list = [s.local_endpoint.port for s in cp.listeners]
            processes.append(
                {
                    "pid": cp.pid,
                    "name": cp.name,
                    "user": identity.user,
                    "executable_path": identity.executable_path,
                    "ports": port_list,
                    "has_finding": any(
                        f for f in result.findings if f.subject and cp.name in f.subject
                    ),
                }
            )

    return {
        "process_count": result.process_count,
        "listener_count": result.listener_count,
        "connection_count": result.connection_count,
        "attention_count": result.attention_count,
        "scan_time": result.scan_time.isoformat(),
        "listeners": listeners,
        "connections": connections,
        "processes": processes,
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "subject": f.subject,
                "status": f.status,
                "reasons": [{"signal": r.signal, "description": r.description} for r in f.reasons],
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }


@app.get("/findings")
async def findings(limit: int = Query(default=100, ge=1, le=500)) -> dict[str, Any]:
    try:
        from sqlalchemy.orm import Session

        from sentinel.storage.database import get_engine, init_db
        from sentinel.storage.finding_repository import FindingRepository

        engine = get_engine()
        init_db(engine)
        with Session(engine) as session:
            records = FindingRepository(session).query_active(limit=limit)
        return {
            "findings": [
                {
                    "id": r.id,
                    "finding_id": r.finding_id,
                    "severity": r.severity,
                    "title": r.title,
                    "subject": r.subject,
                    "status": r.status,
                    "occurred_at": r.occurred_at.isoformat(),
                    "reasons": r.reasons,
                }
                for r in records
            ]
        }
    except Exception as exc:
        logger.error("findings query failed: %s", exc)
        return {"findings": [], "error": str(exc)}


@app.get("/baseline")
async def baseline_list() -> dict[str, Any]:
    try:
        from sqlalchemy.orm import Session

        from sentinel.application.baseline_service import BaselineService
        from sentinel.storage.baseline_repository import BaselineRepository
        from sentinel.storage.database import get_engine, init_db

        engine = get_engine()
        init_db(engine)
        with Session(engine) as session:
            entries = BaselineService(BaselineRepository(session)).list_all()
        return {
            "entries": [
                {
                    "id": e.id,
                    "subject_type": e.subject_type,
                    "subject": e.subject,
                    "reason": e.reason,
                    "added_at": e.added_at.isoformat(),
                }
                for e in entries
            ]
        }
    except Exception as exc:
        return {"entries": [], "error": str(exc)}


@app.websocket("/events")
async def events_ws(websocket: WebSocket) -> None:
    await websocket.accept()
    _ws_clients.append(websocket)
    logger.info("WebSocket client connected (%d total)", len(_ws_clients))
    try:
        while True:
            # Keep the connection alive; events are pushed by _broadcast_event
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping"})
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)
        logger.info("WebSocket client disconnected (%d remaining)", len(_ws_clients))
