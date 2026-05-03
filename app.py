import os
from flask import Flask, request, jsonify, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from detector import analyse_prompt
from logger import log_detection, get_stats

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

if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)