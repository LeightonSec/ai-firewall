import os
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from detector import analyse_prompt
from logger import log_detection, get_stats, query_history

VALID_RISK_LEVELS = {"LOW", "MEDIUM", "HIGH"}
MAX_HISTORY_LIMIT = 500

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

@app.errorhandler(429)
def rate_limit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please wait before submitting again."
    }), 429

@app.route("/")
def index():
    """Serve the main web interface"""
    return render_template("index.html")

@app.route("/analyse", methods=["POST"])
@limiter.limit("10 per minute")
def analyse():
    """Receive prompt and return analysis"""

    data = request.get_json()

    if not data or "prompt" not in data:
        return jsonify({"error": "No prompt provided"}), 400
    
    prompt = data["prompt"].strip()
    
    if not prompt:
        return jsonify({"error": "Empty prompt"}), 400
    
    if len(prompt) > 2000:
        return jsonify({"error": "Prompt too long (max 2000 chars)"}), 400
    
    result = analyse_prompt(prompt)
    result["blocked"] = result["risk_level"] == "HIGH"
    log_detection(result)

    return jsonify(result)

@app.route("/stats")
def stats():
    """Return detection statistics"""
    return jsonify(get_stats())

@app.route("/logs")
def logs():
    """Return recent logs"""
    return jsonify(get_stats()["recent"])

@app.route("/history")
def history():
    """Query persisted detection history.

    Filters: risk_level (LOW/MEDIUM/HIGH), since/until (ISO-8601 timestamps),
    anomalous_only (only steered/degraded responses — the anomaly stream).
    """
    risk_level = request.args.get("risk_level")
    if risk_level:
        risk_level = risk_level.upper()
        if risk_level not in VALID_RISK_LEVELS:
            return jsonify({"error": "Invalid risk_level (use LOW/MEDIUM/HIGH)"}), 400

    anomalous_only = request.args.get("anomalous_only", "").lower() in ("1", "true", "yes")

    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
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