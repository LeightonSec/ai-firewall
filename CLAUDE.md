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
- `app.py` — Flask server, API routes, auth gating, sanitized errors, security headers
- `auth.py` — Dual auth: session login (human) + API key (machine); werkzeug hashes
- `detector.py` — Two-layer detection (keyword scan + Claude API), risk scoring
- `logger.py` — SQLite persistence (detections + stats + history query + legacy importer)
- `templates/index.html` — Web dashboard · `templates/login.html` — login page
- `logs/detections.db` — SQLite detection store (gitignored)
- `.env.example` — Template for required env vars (copy to gitignored .env)
- `Dockerfile` / `.dockerignore` / `docker-compose.yml` — Containerization (non-root, gunicorn)
- `.github/workflows/ci.yml` — CI: offline tests → image build → Trivy scan
- `SECURITY.md` — Threat model and defended pillars (Gate 1–4a)
- `test_gate1.py` / `test_gate2.py` / `test_gate3.py` — Offline unit tests (45 total)
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
✅ Gate 2 — persistence:
   - SQLite store replacing the JSON log; Gate 1 flags (anomalous/degraded/
     short_circuited) are first-class indexed columns
   - /history endpoint with risk_level, date-range, and anomalous_only filters
   - Prompt stored as 100-char prefix + SHA-256 hash, never raw (privacy)
   - One-time legacy JSON importer: `python logger.py import`
✅ Gate 3 — auth & web hardening:
   - Dual auth: session login (human) for dashboard + data endpoints, API key
     (X-API-Key) for POST /analyse — independent domains
   - Hashed env credentials (werkzeug), constant-time compares, SameSite=Strict
   - Sanitized 4xx/5xx handlers (no tracebacks) + security headers
   - CSRF handled by the auth model (no Flask-WTF) — see SECURITY.md §8
✅ Gate 4a — containerization & hardening:
   - Dockerfile (multi-stage, non-root uid 10001, explicit COPYs — no baked secrets)
   - gunicorn (single worker); ProxyFix + HSTS behind TLS; pinned requirements.txt
   - docker-compose (localhost-bound, volume for SQLite, env_file secrets)
   - GitHub Actions CI: 45 offline tests → image build → Trivy (fail on fixable CRIT/HIGH)
   - Live test_detector.py smoke test run with real key: 18/20 (2 misses are Gate 5 tuning)

## Next Steps
- [ ] Gate 4b — cloud deploy: target decision (ECS Fargate vs App Runner), managed
      secrets (Secrets Manager/SSM), HTTPS; set FIREWALL_TRUST_PROXY + FIREWALL_COOKIE_SECURE
- [ ] Gate 5 — detection: split/embedded base64; leetspeak-malware → HIGH; keyword FP reduction
- [ ] Secure RAG pipeline (only if/when retrieval is added — see SECURITY.md)
- [ ] Alert integration with Incident Tracker

## Tech Stack
- Python, Flask, gunicorn
- Anthropic Claude API (claude-haiku-4-5-20251001)
- python-dotenv, SQLite, werkzeug (auth); Docker + GitHub Actions + Trivy (CI/deploy)

## Security Rules
- API key in .env — never committed
- .env, logs/, venv/, .venv/, __pycache__ all gitignored (.env.example IS committed)
- All credentials (login + API key + secret key) from env only; password stored as a hash
- Dashboard + data endpoints require login; POST /analyse requires the X-API-Key header
- Errors are sanitized (no tracebacks); debug stays False; security headers on every response
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