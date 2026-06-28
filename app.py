import os
from flask import (
    Flask, request, jsonify, render_template, session, redirect, url_for
)
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from detector import analyse_prompt
from logger import log_detection, get_stats, query_history
from auth import verify_login, login_required, api_key_required

VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}
MAX_HISTORY_LIMIT = 500

app = Flask(__name__)

# Session security. SECRET_KEY must come from the environment in any real
# deployment; the random fallback keeps local dev working but invalidates
# sessions on restart (acceptable — it never silently ships a hardcoded key).
app.secret_key = os.getenv("FIREWALL_SECRET_KEY") or os.urandom(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    # Secure cookies once served over HTTPS (Gate 4). Opt-in via env so local
    # HTTP dev still works.
    SESSION_COOKIE_SECURE=os.getenv("FIREWALL_COOKIE_SECURE", "").lower() in ("1", "true", "yes"),
)

# Behind a TLS-terminating proxy/load balancer (ALB, App Runner), trust ONE hop
# of X-Forwarded-* so request.is_secure / client IP reflect the real request.
# Without this, HSTS and per-IP rate limiting would see the proxy, not the client.
if os.getenv("FIREWALL_TRUST_PROXY", "").lower() in ("1", "true", "yes"):
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


# --- Security headers + sanitized error handling ---------------------------

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # Minimal CSP — the dashboard is self-contained (no external scripts).
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    # HSTS only over HTTPS (request.is_secure reflects X-Forwarded-Proto when
    # ProxyFix is enabled). Never sent over plain HTTP, where it's meaningless.
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def _error(status, message):
    return jsonify({"error": message}), status

@app.errorhandler(400)
def bad_request(e):
    return _error(400, "Bad request")

@app.errorhandler(401)
def unauthorized(e):
    return _error(401, "Authentication required")

@app.errorhandler(403)
def forbidden(e):
    return _error(403, "Forbidden")

@app.errorhandler(404)
def not_found(e):
    return _error(404, "Not found")

@app.errorhandler(429)
def rate_limit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please wait before submitting again.",
    }), 429

@app.errorhandler(500)
def server_error(e):
    # Never leak tracebacks or internals to the client.
    return _error(500, "Internal server error")


# --- Auth routes ------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    """Human login. Sets a session cookie on success."""
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if verify_login(username, password):
        session["user"] = username
        return redirect(url_for("index"))
    return render_template("login.html", error="Invalid credentials"), 401

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Application routes -----------------------------------------------------

@app.route("/")
def index():
    """Serve the main web interface (redirects to login if unauthenticated)."""
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template("index.html")

@app.route("/analyse", methods=["POST"])
@api_key_required
@limiter.limit("10 per minute")
def analyse():
    """Receive a prompt and return analysis. Machine endpoint — API key required."""
    data = request.get_json(silent=True)

    if not data or "prompt" not in data:
        return _error(400, "No prompt provided")

    prompt = data["prompt"]
    if not isinstance(prompt, str):
        # A non-string prompt (e.g. {"prompt": 123}) must not reach .strip() and
        # 500 — return a clean 400 instead.
        return _error(400, "Prompt must be a string")
    prompt = prompt.strip()

    if not prompt:
        return _error(400, "Empty prompt")

    if len(prompt) > 2000:
        return _error(400, "Prompt too long (max 2000 chars)")

    result = analyse_prompt(prompt)
    result["blocked"] = result["risk_level"] == "HIGH"
    log_detection(result)

    return jsonify(result)

@app.route("/stats")
@login_required
def stats():
    """Return detection statistics"""
    return jsonify(get_stats())

@app.route("/logs")
@login_required
def logs():
    """Return recent logs"""
    return jsonify(get_stats()["recent"])

@app.route("/history")
@login_required
def history():
    """Query persisted detection history.

    Filters: risk_level (LOW/MEDIUM/HIGH), since/until (ISO-8601 timestamps),
    anomalous_only (only steered/degraded responses — the anomaly stream).
    """
    risk_level = request.args.get("risk_level")
    if risk_level:
        risk_level = risk_level.upper()
        if risk_level not in VALID_RISK_LEVELS:
            return _error(400, "Invalid risk_level (use LOW/MEDIUM/HIGH)")

    anomalous_only = request.args.get("anomalous_only", "").lower() in ("1", "true", "yes")

    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        return _error(400, "limit must be an integer")
    limit = max(1, min(limit, MAX_HISTORY_LIMIT))

    results = query_history(
        risk_level=risk_level,
        since=request.args.get("since"),
        until=request.args.get("until"),
        anomalous_only=anomalous_only,
        limit=limit,
    )
    return jsonify({"count": len(results), "results": results})


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
