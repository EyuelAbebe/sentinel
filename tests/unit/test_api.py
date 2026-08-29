"""Unit tests for the FastAPI HTTP endpoints."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient  # noqa: E402

from sentinel.api.app import app  # noqa: E402

client = TestClient(app)


def test_health_returns_ok() -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert "time" in r.json()


def test_classify_known_domain() -> None:
    r = client.get("/classify", params={"domain": "google-analytics.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["category"] == "analytics"
    assert data["organization"] == "Google"
    assert data["confidence"] == 1.0


def test_classify_unknown_domain() -> None:
    r = client.get("/classify", params={"domain": "example.com"})
    assert r.status_code == 200
    data = r.json()
    assert data["category"] == "unknown"
    assert data["confidence"] == 0.0


def test_classify_subdomain() -> None:
    r = client.get("/classify", params={"domain": "cdn.doubleclick.net"})
    assert r.status_code == 200
    assert r.json()["category"] == "advertising"


def test_classify_missing_domain_returns_422() -> None:
    r = client.get("/classify")
    assert r.status_code == 422


def test_findings_returns_list() -> None:
    r = client.get("/findings")
    assert r.status_code == 200
    assert "findings" in r.json()


def test_baseline_returns_list() -> None:
    r = client.get("/baseline")
    assert r.status_code == 200
    assert "entries" in r.json()
