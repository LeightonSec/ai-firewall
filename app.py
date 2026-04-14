import os
from flask import Flask, request, jsonify, render_template
from detector import analyse_prompt
from logger import log_detection, get_stats

app = Flask(__name__)

@app.route("/")
def index():
    """Serve the main web interface"""
    return render_template("index.html")

@app.route("/analyse", methods=["POST"])
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