# CLAUDE.md — AI Firewall

## What This Is
A Flask web application that detects and classifies jailbreak attempts 
against LLMs. Uses two-layer detection — keyword pattern matching and 
Claude API semantic analysis — to assign risk levels to prompts.
Built as part of the LeightonSec SOC Toolkit.

## SOC Toolkit Position
- **Layer:** Analysis
- **Receives from:** Any prompt source, future PCAP Analyser alerts
- **Feeds into:** Future Incident Tracker (response layer), future Unified Dashboard
- **Gap it fills:** AI/LLM threat classification and jailbreak detection

## Architecture
- `app.py` — Flask server, API routes, input validation (2000-char clamp), rate limiting
- `detector.py` — Two-layer detection (keyword scan + Claude API), risk scoring
- `logger.py` — JSON logging and statistics
- `templates/index.html` — Web interface and live dashboard
- `logs/detections.json` — Detection log (gitignored)
- `SECURITY.md` — Threat model and defended pillars (Gate 1)
- `test_gate1.py` — Offline unit tests for the hardening fixes
- `test_detector.py` — End-to-end detection suite (requires a live API key)

## Current Status
✅ Complete and live — LeightonSec/ai-firewall
✅ Keyword detection across 4 attack categories
✅ Claude API semantic classification
✅ Risk scoring LOW/MEDIUM/HIGH
✅ Web dashboard with live stats
✅ JSON logging with timestamps
✅ Rate limiting on /analyse (flask-limiter)
✅ Gate 1 — pipeline hardening:
   - Hardened classifier prompt: per-request random boundary, untrusted content
     framed as hostile data, instructions inside it classified as JAILBREAK
   - Fail-CLOSED output validation: malformed/steered/oversized responses yield a
     None verdict (SUSPICIOUS), never default to CLEAN
   - Tiered short-circuit: unambiguous attack markers classified locally, no API call

## Next Steps
- [ ] SQLite database replacing JSON logs
- [ ] Authentication layer for web interface (Gate 3)
- [ ] Docker containerisation (Gate 4)
- [ ] Split/embedded base64 detection (input-side gap noted in normalise_prompt)
- [ ] Secure RAG pipeline (only if/when retrieval is added — see SECURITY.md)
- [ ] Alert integration with Incident Tracker

## Tech Stack
- Python, Flask
- Anthropic Claude API (claude-haiku-4-5-20251001)
- python-dotenv, JSON

## Security Rules
- API key in .env — never committed
- .env, logs/, venv/, .venv/, __pycache__ all gitignored
- Input validation on all prompts (max 2000 chars)
- Server bound to 127.0.0.1 only
- Classifier prompt hardened against injection: untrusted input is wrapped in a
  per-request random boundary and framed as data, never instructions
- Output fails CLOSED: only an explicit CLEAN verdict can lower risk to LOW;
  anything else (missing/invalid/unavailable verdict) is treated as SUSPICIOUS
- Never trust the API reason string in decision logic — display only

## Conventions
- Detection logic stays in detector.py
- New attack categories added to PATTERNS dict in detector.py
- Logs always written via logger.py
- Risk levels always strings: "LOW", "MEDIUM", "HIGH"
- Never expose the API key in logs or responses