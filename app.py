import os
from collections import defaultdict
from time import time
from flask import Flask, request, jsonify, render_template
from detector import analyse_prompt
from logger import log_detection, get_stats

app = Flask(__name__)

_rate_store: dict = defaultdict(list)
RATE_LIMIT  = 30
RATE_WINDOW = 60


def _is_rate_limited(ip: str) -> bool:
    now = time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT:
        return True
    _rate_store[ip].append(now)
    if len(_rate_store) > 10000:
        _rate_store.clear()
    return False


def _get_ip() -> str:
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        ip = forwarded.split(',')[0].strip()
        return ''.join(c for c in ip if c.isprintable() and c not in '\r\n')[:45] or '0.0.0.0'
    return request.remote_addr or '0.0.0.0'

@app.route("/")
def index():
    """Serve the main web interface"""
    return render_template("index.html")

@app.route("/analyse", methods=["POST"])
def analyse():
    """Receive prompt and return analysis"""
    if _is_rate_limited(_get_ip()):
        return jsonify({"error": "Too many requests"}), 429

    data = request.get_json()

    if not data or "prompt" not in data:
        return jsonify({"error": "No prompt provided"}), 400
    
    prompt = data["prompt"].strip()
    
    if not prompt:
        return jsonify({"error": "Empty prompt"}), 400
    
    if len(prompt) > 2000:
        return jsonify({"error": "Prompt too long (max 2000 chars)"}), 400
    
    result = analyse_prompt(prompt)
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