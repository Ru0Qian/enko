"""
Enko backend tests — pytest suite for server_prod.py endpoints.

Usage:
    cd enko
    pytest tests/ -v

Requires the development dependency set:
    pip install -r requirements-dev.txt
"""
import os
import sys
import pytest
import asyncio

# Ensure web-console is on path so server_prod imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web-console"))

# Override env vars before importing the app
os.environ.setdefault("ENKO_JWT_SECRET", "test-secret-key-for-testing-only-not-production")
os.environ.setdefault("ENKO_ADMIN_USER", "testadmin")
os.environ.setdefault("ENKO_ADMIN_PASS", "testpass123")
os.environ.setdefault("DATABASE_URL", "")  # disable DB for unit tests

from httpx import AsyncClient, ASGITransport


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="module")
def app():
    """Import and return the FastAPI app."""
    from server_prod import app as _app
    return _app


@pytest.fixture(scope="module")
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture(scope="module")
async def auth_token(client):
    """Login and return a valid JWT token."""
    resp = await client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "testpass123",
    })
    if resp.status_code == 200:
        return resp.json()["token"]
    pytest.skip("Cannot login — DB might not be available")


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ─── Auth Tests ───────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_login_success(client):
    resp = await client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "testpass123",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert data["username"] == "testadmin"
    assert data["expires_in"] > 0


@pytest.mark.anyio
async def test_login_wrong_password(client):
    resp = await client.post("/api/auth/login", json={
        "username": "testadmin",
        "password": "wrongpassword",
    })
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_protected_endpoint_no_token(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_protected_endpoint_invalid_token(client):
    resp = await client.get("/api/health", headers={"Authorization": "Bearer invalid.token.here"})
    assert resp.status_code == 401


@pytest.mark.anyio
async def test_health_with_token(client, auth_token):
    resp = await client.get("/api/health", headers=auth_headers(auth_token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "version" in data


# ─── Deep Health Tests ────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_deep_health_no_auth_required(client):
    resp = await client.get("/api/health/deep")
    # Should work without auth (monitoring probe)
    assert resp.status_code in (200, 503)
    data = resp.json()
    assert "timestamp" in data
    assert "filesystem" in data
    assert "packer" in data


# ─── Metrics Tests ────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_metrics_endpoint(client):
    resp = await client.get("/api/metrics")
    assert resp.status_code == 200
    assert "enko_http_requests_total" in resp.text


# ─── Upload Tests ─────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_upload_no_file(client, auth_token):
    resp = await client.post("/api/upload", headers=auth_headers(auth_token))
    assert resp.status_code == 422  # validation error — no file


@pytest.mark.anyio
async def test_upload_empty_file(client, auth_token):
    resp = await client.post(
        "/api/upload",
        headers=auth_headers(auth_token),
        files={"file": ("test.apk", b"", "application/octet-stream")},
    )
    assert resp.status_code == 400
    assert "EMPTY_FILE" in resp.text or "空" in resp.text


# ─── Protection Map Tests ────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_save_protection_map_empty(client, auth_token):
    resp = await client.post(
        "/api/save-protection-map",
        headers={**auth_headers(auth_token), "Content-Type": "application/json"},
        json={"content": ""},
    )
    assert resp.status_code == 400
    assert "EMPTY_MAP" in resp.text


@pytest.mark.anyio
async def test_save_protection_map_invalid_level(client, auth_token):
    resp = await client.post(
        "/api/save-protection-map",
        headers={**auth_headers(auth_token), "Content-Type": "application/json"},
        json={"content": "Lcom/example/Test;->foo()V 5"},
    )
    assert resp.status_code == 400
    assert "INVALID_LEVEL" in resp.text


@pytest.mark.anyio
async def test_save_protection_map_valid(client, auth_token):
    content = "Lcom/example/Test;->foo()V 2\nLcom/example/Test;->bar(I)Z 1"
    resp = await client.post(
        "/api/save-protection-map",
        headers={**auth_headers(auth_token), "Content-Type": "application/json"},
        json={"content": content},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "path" in data


@pytest.mark.anyio
async def test_save_protection_map_too_large(client, auth_token):
    huge_content = ("Lcom/example/Test;->foo()V 2\n" * 50000)  # >500KB
    resp = await client.post(
        "/api/save-protection-map",
        headers={**auth_headers(auth_token), "Content-Type": "application/json"},
        json={"content": huge_content},
    )
    assert resp.status_code == 413


# ─── CSRF Tests ──────────────────────────────────────────────────────────────

@pytest.mark.anyio
async def test_csrf_blocks_cross_origin(client, auth_token):
    resp = await client.post(
        "/api/save-protection-map",
        headers={
            **auth_headers(auth_token),
            "Content-Type": "application/json",
            "Origin": "https://evil.example.com",
            "Host": "test",
        },
        json={"content": "Lcom/x/T;->a()V 1"},
    )
    assert resp.status_code == 403
