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
- `app.py` — Flask server, API routes, input validation
- `detector.py` — Two-layer detection (keyword scan + Claude API), risk scoring
- `logger.py` — JSON logging and statistics
- `templates/index.html` — Web interface and live dashboard
- `logs/detections.json` — Detection log (gitignored)

## Current Status
✅ Complete and live — LeightonSec/ai-firewall
✅ Keyword detection across 4 attack categories
✅ Claude API semantic classification
✅ Risk scoring LOW/MEDIUM/HIGH
✅ Web dashboard with live stats
✅ JSON logging with timestamps
✅ Prompt injection hardened system prompt

## Next Steps
- [ ] SQLite database replacing JSON logs
- [ ] Rate limiting to prevent API abuse
- [ ] Authentication layer for web interface
- [ ] Docker containerisation
- [ ] Alert integration with Incident Tracker

## Tech Stack
- Python, Flask
- Anthropic Claude API (claude-haiku-4-5-20251001)
- python-dotenv, JSON

## Security Rules
- API key in .env — never committed
- .env, logs/, venv/, __pycache__ all gitignored
- Input validation on all prompts (max 2000 chars)
- Server bound to 127.0.0.1 only
- System prompt hardened against prompt injection

## Conventions
- Detection logic stays in detector.py
- New attack categories added to PATTERNS dict in detector.py
- Logs always written via logger.py
- Risk levels always strings: "LOW", "MEDIUM", "HIGH"
- Never expose the API key in logs or responses