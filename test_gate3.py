"""
Gate 3 — auth + error hardening tests (offline, no live API).

Covers the dual auth model (session login for humans, API key for /analyse),
sanitized error handling, and security headers. Uses Flask's test_client; the
detector is monkeypatched so POST /analyse never makes a network call.
"""
import secrets

import pytest
from werkzeug.security import generate_password_hash

import app as app_module
import auth


# Test fixtures generated at runtime — no credential literals live in the repo
# (a hardcoded value here would, correctly, trip secret scanners).
USERNAME = "analyst"
PASSWORD = "pw-" + secrets.token_hex(8)
API_KEY = "key-" + secrets.token_hex(8)


@pytest.fixture
def client(monkeypatch):
    # Configure credentials via env (read at request time by auth.py).
    monkeypatch.setenv("FIREWALL_USERNAME", USERNAME)
    monkeypatch.setenv("FIREWALL_PASSWORD_HASH", generate_password_hash(PASSWORD))
    monkeypatch.setenv("FIREWALL_API_KEY", API_KEY)

    flask_app = app_module.app
    flask_app.config["TESTING"] = True
    flask_app.secret_key = "test-secret"

    # Keep POST /analyse offline.
    monkeypatch.setattr(app_module, "analyse_prompt",
                        lambda p: {"prompt": p, "risk_level": "LOW",
                                   "keyword_matches": {}, "keyword_score": 0,
                                   "api_verdict": "CLEAN", "api_confidence": "HIGH",
                                   "api_reason": "ok"})
    monkeypatch.setattr(app_module, "log_detection", lambda result: None)

    return flask_app.test_client()


def login(client, user=USERNAME, pw=PASSWORD):
    return client.post("/login", data={"username": user, "password": pw})


# --- Human/session auth on data endpoints ----------------------------------

@pytest.mark.parametrize("path", ["/stats", "/logs", "/history"])
def test_data_endpoints_require_login(client, path):
    r = client.get(path)
    assert r.status_code == 401
    assert r.get_json()["error"]

@pytest.mark.parametrize("path", ["/stats", "/logs", "/history"])
def test_data_endpoints_ok_after_login(client, path, monkeypatch):
    # Keep the logger offline/empty.
    monkeypatch.setattr(app_module, "get_stats",
                        lambda: {"total": 0, "high": 0, "medium": 0, "low": 0, "recent": []})
    monkeypatch.setattr(app_module, "query_history", lambda **kw: [])
    login(client)
    assert client.get(path).status_code == 200

def test_dashboard_redirects_to_login_when_anonymous(client):
    r = client.get("/")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]

def test_login_rejects_bad_credentials(client):
    assert client.post("/login", data={"username": USERNAME, "password": "wrong"}).status_code == 401
    assert client.post("/login", data={"username": "nope", "password": PASSWORD}).status_code == 401

def test_logout_clears_session(client):
    login(client)
    assert client.get("/stats").status_code == 200
    client.get("/logout")
    assert client.get("/stats").status_code == 401


# --- Machine/API-key auth on /analyse --------------------------------------

def test_analyse_requires_api_key(client):
    r = client.post("/analyse", json={"prompt": "hello"})
    assert r.status_code == 401

def test_analyse_rejects_wrong_api_key(client):
    r = client.post("/analyse", json={"prompt": "hello"}, headers={"X-API-Key": "nope"})
    assert r.status_code == 401

def test_analyse_accepts_valid_api_key(client):
    r = client.post("/analyse", json={"prompt": "hello"}, headers={"X-API-Key": API_KEY})
    assert r.status_code == 200
    assert r.get_json()["risk_level"] == "LOW"

def test_analyse_rejects_non_string_prompt(client):
    # {"prompt": 123} must yield a clean 400, not a 500 from .strip() on an int.
    r = client.post("/analyse", json={"prompt": 123}, headers={"X-API-Key": API_KEY})
    assert r.status_code == 400
    assert r.get_json()["error"] == "Prompt must be a string"

def test_analyse_does_not_use_session(client):
    # A logged-in human still cannot POST /analyse without the API key —
    # the two auth domains are independent.
    login(client)
    assert client.post("/analyse", json={"prompt": "hi"}).status_code == 401


# --- Error hardening + headers ---------------------------------------------

def test_404_is_sanitized_json(client):
    r = client.get("/no-such-route")
    assert r.status_code == 404
    assert r.get_json()["error"] == "Not found"

def test_security_headers_present(client):
    r = client.get("/login")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]

def test_500_handler_hides_internals(client, monkeypatch):
    # Force an unexpected error inside a handler and assert nothing leaks.
    monkeypatch.setattr(app_module, "get_stats",
                        lambda: (_ for _ in ()).throw(RuntimeError("secret internal detail")))
    app_module.app.config["PROPAGATE_EXCEPTIONS"] = False
    login(client)
    r = client.get("/stats")
    assert r.status_code == 500
    body = r.get_data(as_text=True)
    assert "secret internal detail" not in body
    assert "Traceback" not in body
