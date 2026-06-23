"""
Detection persistence — SQLite backend (Gate 2).

Replaces the previous flat JSON log. The public interface is unchanged
(``log_detection(result)`` and ``get_stats()``) so callers and the Gate 1
detection logic do not need to change. Adds ``query_history`` for the /history
endpoint and ``import_legacy_json`` for one-time migration of the old log.

Privacy: the raw prompt is NEVER stored. Each detection keeps a 100-char prefix
(enough to recognise a pattern) plus a SHA-256 hash of the full prompt (dedup /
"have we seen this exact attack"). Full-prompt retention is a deployment-time
policy decision, not baked into the tool.
"""
import os
import json
import sqlite3
import hashlib
from datetime import datetime, timezone

DB_FILE = "logs/detections.db"
LEGACY_JSON = "logs/detections.json"
PROMPT_PREFIX_LEN = 100

_SCHEMA = """
CREATE TABLE IF NOT EXISTS detections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    prompt_prefix   TEXT    NOT NULL,
    prompt_hash     TEXT    NOT NULL,
    risk_level      TEXT    NOT NULL,
    keyword_score   INTEGER NOT NULL,
    keyword_matches TEXT,
    api_verdict     TEXT,
    api_confidence  TEXT,
    api_reason      TEXT,
    anomalous       INTEGER NOT NULL DEFAULT 0,
    degraded        INTEGER NOT NULL DEFAULT 0,
    short_circuited INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_timestamp ON detections(timestamp);
CREATE INDEX IF NOT EXISTS idx_risk      ON detections(risk_level);
CREATE INDEX IF NOT EXISTS idx_anomalous ON detections(anomalous);
"""


def _connect() -> sqlite3.Connection:
    parent = os.path.dirname(DB_FILE)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create the table and indices if they do not exist (idempotent).

    NOTE (known inefficiency, acceptable for a local/portfolio tool): this is
    called on every log_detection/get_stats/query_history call, so each opens a
    connection just to re-assert the schema. For production, init once at app
    startup and reuse a connection/pool instead.
    """
    conn = _connect()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _prompt_fields(prompt: str):
    """Return (100-char prefix, sha256 hex). Never returns the raw prompt."""
    prompt = prompt or ""
    prefix = prompt[:PROMPT_PREFIX_LEN]
    digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    return prefix, digest


def _row_values(entry: dict) -> tuple:
    """Map a detection/log dict to the column tuple. Tolerates pre-Gate-1
    entries that lack the api_* flag fields (default to 0)."""
    prefix, digest = _prompt_fields(entry.get("prompt", ""))
    matches = entry.get("keyword_matches")
    return (
        entry.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        prefix,
        digest,
        entry["risk_level"],
        int(entry.get("keyword_score", 0)),
        json.dumps(matches) if matches is not None else None,
        entry.get("api_verdict"),
        entry.get("api_confidence"),
        entry.get("api_reason"),
        int(bool(entry.get("api_anomalous", False))),
        int(bool(entry.get("api_degraded", False))),
        int(bool(entry.get("api_short_circuited", False))),
    )


_INSERT = """
INSERT INTO detections
    (timestamp, prompt_prefix, prompt_hash, risk_level, keyword_score,
     keyword_matches, api_verdict, api_confidence, api_reason,
     anomalous, degraded, short_circuited)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def log_detection(result: dict) -> None:
    """Persist a detection result. Stable signature (unchanged from Gate 1)."""
    init_db()
    conn = _connect()
    try:
        conn.execute(_INSERT, _row_values(result))
        conn.commit()
    finally:
        conn.close()


def _decode_row(row: sqlite3.Row) -> dict:
    d = dict(row)
    if d.get("keyword_matches"):
        try:
            d["keyword_matches"] = json.loads(d["keyword_matches"])
        except (ValueError, TypeError):
            pass
    for flag in ("anomalous", "degraded", "short_circuited"):
        d[flag] = bool(d[flag])
    return d


def get_stats() -> dict:
    """Summary statistics. Stable signature (unchanged from Gate 1)."""
    init_db()
    conn = _connect()
    try:
        counts = {
            r["risk_level"]: r["n"]
            for r in conn.execute(
                "SELECT risk_level, COUNT(*) AS n FROM detections GROUP BY risk_level"
            )
        }
        recent = [
            _decode_row(r)
            for r in conn.execute(
                "SELECT * FROM detections ORDER BY id DESC LIMIT 5"
            )
        ]
    finally:
        conn.close()
    return {
        "total": sum(counts.values()),
        "high": counts.get("HIGH", 0),
        "medium": counts.get("MEDIUM", 0),
        "low": counts.get("LOW", 0),
        "recent": recent,
    }


def query_history(risk_level=None, since=None, until=None,
                  anomalous_only=False, limit=100) -> list:
    """Filtered detection history for the /history endpoint.

    - risk_level: exact match (LOW/MEDIUM/HIGH)
    - since/until: ISO-8601 timestamp bounds (inclusive)
    - anomalous_only: only responses flagged anomalous OR degraded
      (the classifier-manipulation / outage stream)
    """
    init_db()
    clauses, params = [], []
    if risk_level:
        clauses.append("risk_level = ?")
        params.append(risk_level)
    if since:
        clauses.append("timestamp >= ?")
        params.append(since)
    if until:
        clauses.append("timestamp <= ?")
        params.append(until)
    if anomalous_only:
        clauses.append("(anomalous = 1 OR degraded = 1)")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT * FROM detections {where} ORDER BY id DESC LIMIT ?"
    params.append(int(limit))

    conn = _connect()
    try:
        rows = [_decode_row(r) for r in conn.execute(sql, params)]
    finally:
        conn.close()
    return rows


def import_legacy_json(path: str = LEGACY_JSON) -> int:
    """One-time migration of the old flat JSON log into SQLite. Returns the
    number of rows imported. Field mapping handles the api_*->flag rename and
    defaults missing (pre-Gate-1) flags to 0. The raw prompt is hashed on
    import, never stored. Safe no-op if the file is absent."""
    if not os.path.exists(path):
        return 0
    with open(path, "r") as f:
        entries = json.load(f)
    init_db()
    conn = _connect()
    try:
        conn.executemany(_INSERT, [_row_values(e) for e in entries])
        conn.commit()
    finally:
        conn.close()
    return len(entries)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "import":
        n = import_legacy_json()
        print(f"Imported {n} legacy detection(s) from {LEGACY_JSON} into {DB_FILE}.")
    else:
        print("Usage: python logger.py import   # migrate logs/detections.json -> SQLite")
