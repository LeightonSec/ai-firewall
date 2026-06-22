"""
Authentication for the AI Firewall (Gate 3).

Dual model, matching the two kinds of caller:
- Humans log in (session cookie) to view the dashboard and detection history.
- Machines call POST /analyse with an API key header (X-API-Key).

Credentials come from environment variables ONLY. The human password is stored
as a werkzeug hash, never plaintext. Comparisons are constant-time. No new
dependencies — werkzeug ships with Flask.

Setup: generate a password hash for FIREWALL_PASSWORD_HASH with
    python auth.py hash <password>
"""
import os
import hmac
from functools import wraps

from flask import session, request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash

API_KEY_HEADER = "X-API-Key"


def verify_login(username: str, password: str) -> bool:
    """True only if both the username and the hashed password match the
    configured credentials. Returns False (not an error) if unconfigured."""
    expected_user = os.getenv("FIREWALL_USERNAME")
    password_hash = os.getenv("FIREWALL_PASSWORD_HASH")
    if not expected_user or not password_hash:
        return False
    user_ok = hmac.compare_digest(username or "", expected_user)
    # check_password_hash is constant-time internally.
    pass_ok = check_password_hash(password_hash, password or "")
    return user_ok and pass_ok


def verify_api_key(provided: str) -> bool:
    """Constant-time compare of a presented API key against FIREWALL_API_KEY."""
    expected = os.getenv("FIREWALL_API_KEY")
    if not expected or not provided:
        return False
    return hmac.compare_digest(provided, expected)


def login_required(f):
    """Gate human/session endpoints. Returns 401 JSON if not logged in.

    (The dashboard route handles its own redirect-to-login for browser UX;
    these JSON data endpoints answer 401 so programmatic callers get a clear
    machine-readable response.)
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return wrapper


def api_key_required(f):
    """Gate machine endpoints. Returns 401 JSON without a valid API key."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not verify_api_key(request.headers.get(API_KEY_HEADER, "")):
            return jsonify({"error": "Valid API key required"}), 401
        return f(*args, **kwargs)
    return wrapper


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "hash":
        print(generate_password_hash(sys.argv[2]))
    else:
        print("Usage: python auth.py hash <password>")
