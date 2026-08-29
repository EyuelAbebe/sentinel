from __future__ import annotations

import json
from typing import Any

from sentinel.application.scan_service import ScanResult


def render_scan_result_json(result: ScanResult) -> str:
    data: dict[str, Any] = {
        "scan_time": result.scan_time.isoformat(),
        "summary": {
            "processes": result.process_count,
            "listening_ports": result.listener_count,
            "connections": result.connection_count,
            "attention": result.attention_count,
        },
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "title": f.title,
                "subject": f.subject,
                "reasons": [{"signal": r.signal, "description": r.description} for r in f.reasons],
            }
            for f in result.findings
        ],
        "errors": result.errors,
    }
    return json.dumps(data, indent=2)
