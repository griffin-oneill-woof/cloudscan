"""API-level tests: auth and CORS. Reloads cloudscan.api per test since it reads env vars (API_KEY,
CORS origins) at import time — these are the settings a real deployment depends on, so they're
worth locking down with real requests through FastAPI, not just unit-testing the helper function."""
import importlib

from fastapi.testclient import TestClient


def load_api(monkeypatch, api_key=None, cors=None):
    if api_key is None:
        monkeypatch.delenv("CLOUDSCAN_API_KEY", raising=False)
    else:
        monkeypatch.setenv("CLOUDSCAN_API_KEY", api_key)
    if cors is None:
        monkeypatch.delenv("CLOUDSCAN_CORS", raising=False)
    else:
        monkeypatch.setenv("CLOUDSCAN_CORS", cors)
    import cloudscan.api as api_mod
    importlib.reload(api_mod)
    return api_mod


def test_open_by_default_when_no_api_key_set(monkeypatch):
    api_mod = load_api(monkeypatch, api_key=None)
    client = TestClient(api_mod.app)
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/recent").status_code == 200


def test_api_key_required_once_set(monkeypatch):
    api_mod = load_api(monkeypatch, api_key="secret123")
    client = TestClient(api_mod.app)
    assert client.get("/api/recent").status_code == 401
    assert client.get("/api/recent", headers={"X-Api-Key": "wrong"}).status_code == 401
    assert client.get("/api/recent", headers={"X-Api-Key": "secret123"}).status_code == 200
    assert client.get("/api/recent?key=secret123").status_code == 200
    # /api/health stays open even with a key configured — it's just the collector list.
    assert client.get("/api/health").status_code == 200


def test_batch_endpoint_accepts_header_key(monkeypatch):
    api_mod = load_api(monkeypatch, api_key="secret123")
    client = TestClient(api_mod.app)
    assert client.post("/api/batch", json={"queries": ["acme.com"]}).status_code == 401
    r = client.post("/api/batch", json={"queries": []}, headers={"X-Api-Key": "secret123"})
    # empty queries list fails Pydantic validation (min_length=1), not auth — 401 would mean auth ran first
    assert r.status_code != 401


def test_cors_closed_by_default(monkeypatch):
    api_mod = load_api(monkeypatch, cors=None)
    client = TestClient(api_mod.app)
    r = client.get("/api/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


def test_cors_opens_only_for_configured_origin(monkeypatch):
    api_mod = load_api(monkeypatch, cors="https://good.example")
    client = TestClient(api_mod.app)
    allowed = client.options("/api/health", headers={
        "Origin": "https://good.example", "Access-Control-Request-Method": "GET"})
    assert allowed.headers.get("access-control-allow-origin") == "https://good.example"
    blocked = client.options("/api/health", headers={
        "Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in blocked.headers
