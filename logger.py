
import json
import os
from datetime import datetime

LOG_FILE = "logs/detections.json"

def ensure_log_file():
    """Create log file if it doesn't exist"""
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)

def log_detection(result: dict):
    """Append a detection result to the log"""
    ensure_log_file()
    
    with open(LOG_FILE, "r") as f:
        logs = json.load(f)
    
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "prompt": result["prompt"],
        "risk_level": result["risk_level"],
        "api_verdict": result["api_verdict"],
        "api_confidence": result["api_confidence"],
        "api_reason": result["api_reason"],
        "keyword_score": result["keyword_score"],
        "keyword_matches": result["keyword_matches"]
    }
    
    logs.append(entry)
    
    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)

def get_stats() -> dict:
    """Return summary statistics from logs"""
    ensure_log_file()
    
    with open(LOG_FILE, "r") as f:
        logs = json.load(f)
    
    total = len(logs)
    high = sum(1 for l in logs if l["risk_level"] == "HIGH")
    medium = sum(1 for l in logs if l["risk_level"] == "MEDIUM")
    low = sum(1 for l in logs if l["risk_level"] == "LOW")
    
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low,
        "recent": logs[-5:] if logs else []
    }