# syntax=docker/dockerfile:1

# --- Stage 1: build dependencies into an isolated venv ---
FROM python:3.13-slim AS build
WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 2: minimal runtime ---
FROM python:3.13-slim AS runtime

# Non-root user — a security tool should not run its own container as root.
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=build /opt/venv /opt/venv
# Copy ONLY what runs — never the repo wholesale, so .env/tests/venv can't leak in.
COPY --chown=appuser:appuser app.py auth.py detector.py logger.py ./
COPY --chown=appuser:appuser templates/ ./templates/

# SQLite store lives here; mount a volume to persist across restarts.
RUN mkdir -p /app/logs && chown appuser:appuser /app/logs
USER appuser

EXPOSE 5000

# /login is an unauthenticated 200 — a cheap liveness probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/login').status==200 else 1)"

# Single worker keeps the in-memory rate limiter and SQLite coherent.
# Multi-worker scaling (Gate 4b) needs Redis for the limiter + a managed DB.
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--timeout", "30", "app:app"]
