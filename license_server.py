
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "usage.db"
SERVER_API_KEY = os.environ.get("SERVER_API_KEY", "").strip()

OFFLINE_AFTER_SECONDS = 120


def now_utc():
    return datetime.now(timezone.utc)


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS installations (
                installation_id TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                launch_count INTEGER NOT NULL DEFAULT 1,
                app_version TEXT NOT NULL DEFAULT ''
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS usage_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                installation_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                app_version TEXT NOT NULL DEFAULT ''
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_started
            ON usage_sessions(started_at)
        """)

        conn.commit()


init_db()


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not SERVER_API_KEY:
            return jsonify({
                "status": "error",
                "message": "Admin API key is not configured"
            }), 503

        if request.headers.get("X-API-Key", "") != SERVER_API_KEY:
            return jsonify({
                "status": "forbidden",
                "message": "Invalid API key"
            }), 403

        return fn(*args, **kwargs)

    return wrapper


@app.get("/")
def health():
    return jsonify({
        "status": "ok",
        "service": "WarZ Usage Monitor"
    })


@app.post("/usage/heartbeat")
def usage_heartbeat():
    data = request.get_json(silent=True) or {}

    installation_id = str(
        data.get("installation_id", "")
    ).strip()

    event = str(
        data.get("event", "heartbeat")
    ).strip().lower()

    app_version = str(
        data.get("app_version", "")
    )[:32]

    if not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f-]{27,}",
        installation_id,
        re.I
    ):
        return jsonify({
            "status": "error",
            "message": "Invalid installation ID"
        }), 400

    if event not in ("launch", "heartbeat"):
        event = "heartbeat"

    now = now_utc().isoformat()

    with get_db() as conn:

        existing = conn.execute(
            """
            SELECT installation_id
            FROM installations
            WHERE installation_id = ?
            """,
            (installation_id,)
        ).fetchone()

        if existing:
            conn.execute("""
                UPDATE installations
                SET last_seen = ?,
                    app_version = ?,
                    launch_count = launch_count + ?
                WHERE installation_id = ?
            """, (
                now,
                app_version,
                1 if event == "launch" else 0,
                installation_id
            ))

        else:
            conn.execute("""
                INSERT INTO installations
                (installation_id, first_seen, last_seen,
                 launch_count, app_version)
                VALUES (?, ?, ?, 1, ?)
            """, (
                installation_id,
                now,
                now,
                app_version
            ))

        if event == "launch":
            conn.execute("""
                INSERT INTO usage_sessions
                (installation_id, started_at, app_version)
                VALUES (?, ?, ?)
            """, (
                installation_id,
                now,
                app_version
            ))

        conn.commit()

    return jsonify({"status": "ok"}), 200


@app.get("/admin/stats")
@require_api_key
def admin_stats():

    now = now_utc()

    today_start = now.replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0
    ).isoformat()

    online_cutoff = (
        now - timedelta(seconds=OFFLINE_AFTER_SECONDS)
    ).isoformat()

    with get_db() as conn:

        total = conn.execute(
            "SELECT COUNT(*) FROM installations"
        ).fetchone()[0]

        online = conn.execute(
            """
            SELECT COUNT(*)
            FROM installations
            WHERE last_seen >= ?
            """,
            (online_cutoff,)
        ).fetchone()[0]

        today = conn.execute(
            """
            SELECT COUNT(DISTINCT installation_id)
            FROM usage_sessions
            WHERE started_at >= ?
            """,
            (today_start,)
        ).fetchone()[0]

        launches = conn.execute(
            """
            SELECT COUNT(*)
            FROM usage_sessions
            WHERE started_at >= ?
            """,
            (today_start,)
        ).fetchone()[0]

    return jsonify({
        "status": "ok",
        "total_installations": total,
        "online_installations": online,
        "active_today": today,
        "launches_today": launches,
        "offline_after_seconds": OFFLINE_AFTER_SECONDS,
        "server_time": now.isoformat()
    })


@app.get("/admin/recent")
@require_api_key
def admin_recent():

    try:
        limit = max(
            1,
            min(int(request.args.get("limit", "50")), 200)
        )
    except ValueError:
        limit = 50

    with get_db() as conn:
        rows = conn.execute("""
            SELECT installation_id, started_at, app_version
            FROM usage_sessions
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

    return jsonify({
        "status": "ok",
        "sessions": [dict(row) for row in rows]
    })


@app.get("/admin")
def admin_dashboard():

    path = BASE_DIR / "admin.html"

    if not path.is_file():
        return "admin.html not found", 404

    return send_file(path)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000"))
    )
