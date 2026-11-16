"""Unit tests for ChronoTrace FastAPI Gateway and Demo Auth APIs."""

import pytest
import os
import sys
from fastapi.testclient import TestClient

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api.main import app

client = TestClient(app)


def test_api_health():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ONLINE"
    assert data["rule_0_enforced"] is True


def test_google_auth_url():
    res = client.get("/api/v1/auth/google/url")
    assert res.status_code == 200
    data = res.json()
    assert "authorization_url" in data
    assert "code_challenge" in data
    assert "accounts.google.com" in data["authorization_url"]


def test_google_auth_verify():
    payload = {
        "code": "demo-code",
        "email": "test_analyst@chronotrace.soc",
        "name": "Specialist Jane Doe"
    }
    res = client.post("/api/v1/auth/google/verify", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["authenticated"] is True
    assert data["auth_provider"] == "google"
    assert "access_token" in data
    assert data["user"]["email"] == "test_analyst@chronotrace.soc"


def test_enterprise_sso():
    payload = {
        "username": "commander@chronotrace.soc",
        "passphrase": "DefenseSecure2026!",
        "clearance_level": "L3 Lead Forensic Specialist"
    }
    res = client.post("/api/v1/auth/enterprise/sso", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["authenticated"] is True
    assert "session_token" in data
    assert data["clearance_granted"] == "L3 Lead Forensic Specialist"


def test_investigations_and_chain():
    res = client.get("/api/v1/investigations")
    assert res.status_code == 200
    invs = res.json()
    assert isinstance(invs, list)
    if invs:
        inv_id = invs[0]["id"]
        c_res = client.get(f"/api/v1/investigations/{inv_id}/chain")
        assert c_res.status_code == 200
        chain_data = c_res.json()
        assert "merkle_root" in chain_data


def test_investigation_lifecycle_and_deletion():
    # 1. Protection of demo baseline
    del_demo = client.delete("/api/v1/investigations/inv-demo-01")
    assert del_demo.status_code == 400
    assert "protected" in del_demo.json()["detail"].lower()

    # 2. 404 on nonexistent case
    del_missing = client.delete("/api/v1/investigations/inv-nonexistent-999")
    assert del_missing.status_code == 404

    # 3. Create, verify and delete custom case
    test_id = "test-inv-api-lifecycle"
    create_res = client.post("/api/v1/investigations", json={
        "id": test_id,
        "name": "API Test Investigation Case",
        "description": "Lifecycle test"
    })
    assert create_res.status_code == 201
    assert create_res.json()["id"] == test_id

    # Verify retrieval
    get_res = client.get(f"/api/v1/investigations/{test_id}")
    assert get_res.status_code == 200
    assert get_res.json()["investigation"]["name"] == "API Test Investigation Case"

    # Delete custom case
    del_res = client.delete(f"/api/v1/investigations/{test_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "success"

    # Confirm it's gone
    get_after = client.get(f"/api/v1/investigations/{test_id}")
    assert get_after.status_code == 404
