import hashlib
import os
import sqlite3
from datetime import date, datetime, time, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, send_file

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "licenses.db"

# ตั้งค่า SERVER_API_KEY ใน Render > Environment
# ห้ามนำค่านี้ไปใส่ในโปรแกรม EXE
SERVER_API_KEY = os.environ.get("SERVER_API_KEY", "").strip()


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS licenses (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT    NOT NULL UNIQUE,
                hwid_bound  TEXT    DEFAULT NULL,
                expire_date TEXT    NOT NULL,
                is_active   INTEGER NOT NULL DEFAULT 1,
                note        TEXT    DEFAULT '',
                created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
                last_seen   TEXT    DEFAULT NULL
            )
        """)
        conn.commit()


init_db()


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Fail closed หากยังไม่ได้ตั้งค่า secret บน Render
        if not SERVER_API_KEY:
            app.logger.error("SERVER_API_KEY is not configured")
            return jsonify({
                "status": "error",
                "message": "Server admin authentication is not configured"
            }), 500

        supplied_key = request.headers.get("X-API-Key", "")
        if supplied_key != SERVER_API_KEY:
            return jsonify({
                "status": "forbidden",
                "message": "Invalid API key"
            }), 403
        return f(*args, **kwargs)
    return decorated


def hash_hwid(hwid: str) -> str:
    return hashlib.sha256(hwid.encode("utf-8")).hexdigest()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_expiry(value: str) -> datetime:
    """
    รองรับ YYYY-MM-DD (หมดอายุเมื่อจบวันนั้น UTC)
    และ ISO datetime เช่น 2026-12-31T23:59:59+00:00
    """
    value = value.strip()
    try:
        parsed_date = date.fromisoformat(value)
        return datetime.combine(
            parsed_date, time.max, tzinfo=timezone.utc
        )
    except ValueError:
        parsed_dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed_dt.tzinfo is None:
            parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
        return parsed_dt.astimezone(timezone.utc)


@app.route("/", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "WarZ License API"
    }), 200


@app.route("/check", methods=["POST"])
def check_license():
    """
    Public endpoint สำหรับโปรแกรมลูกค้า:
    ไม่ต้องใช้ SERVER_API_KEY เพราะ EXE ไม่ควรเก็บ admin secret
    """
    data = request.get_json(silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    hwid_raw = str(data.get("hwid", "")).strip()

    if not license_key or not hwid_raw:
        return jsonify({
            "status": "invalid",
            "message": "Missing license_key or hwid"
        }), 400

    hwid_hash = hash_hwid(hwid_raw)

    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM licenses WHERE license_key = ?",
            (license_key,)
        ).fetchone()

        if not row:
            return jsonify({
                "status": "invalid",
                "message": "License key not found"
            }), 200

        if not row["is_active"]:
            return jsonify({
                "status": "invalid",
                "message": "License is disabled"
            }), 200

        try:
            expire_dt = parse_expiry(row["expire_date"])
        except ValueError:
            app.logger.exception("Invalid expire_date for license record")
            return jsonify({
                "status": "invalid",
                "message": "Invalid expire_date in database"
            }), 200

        if now_utc() > expire_dt:
            return jsonify({
                "status": "expired",
                "message": f"License expired on {row['expire_date']}",
                "expire_date": row["expire_date"]
            }), 200

        if not row["hwid_bound"]:
            conn.execute(
                """UPDATE licenses
                   SET hwid_bound = ?, last_seen = ?
                   WHERE license_key = ?""",
                (hwid_hash, now_utc().isoformat(), license_key)
            )
        elif row["hwid_bound"] != hwid_hash:
            return jsonify({
                "status": "hwid_mismatch",
                "message": "License is bound to a different machine"
            }), 200
        else:
            conn.execute(
                """UPDATE licenses SET last_seen = ?
                   WHERE license_key = ?""",
                (now_utc().isoformat(), license_key)
            )

        conn.commit()

    return jsonify({
        "status": "valid",
        "message": "License OK",
        "expire_date": row["expire_date"]
    }), 200


@app.route("/admin/add", methods=["POST"])
@require_api_key
def admin_add():
    data = request.get_json(silent=True) or {}
    key = str(data.get("license_key", "")).strip()
    expire_date = str(data.get("expire_date", "")).strip()
    note = str(data.get("note", "")).strip()

    if not key or not expire_date:
        return jsonify({
            "status": "error",
            "message": "license_key and expire_date required"
        }), 400

    try:
        # ตรวจสอบรูปแบบวันหรือ ISO datetime
        parse_expiry(expire_date)
    except ValueError:
        return jsonify({
            "status": "error",
            "message": "expire_date format must be YYYY-MM-DD or ISO datetime"
        }), 400

    try:
        with get_db() as conn:
            conn.execute(
                """INSERT INTO licenses (license_key, expire_date, note)
                   VALUES (?, ?, ?)""",
                (key, expire_date, note)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({
            "status": "error",
            "message": "license_key already exists"
        }), 409

    return jsonify({
        "status": "ok",
        "message": f"Added {key} expires {expire_date}"
    }), 201


@app.route("/admin", methods=["GET"])
def admin_dashboard():
    admin_file = BASE_DIR / "admin.html"
    if not admin_file.is_file():
        return "admin.html not found; include it in the Render deployment", 404
    return send_file(admin_file)


if __name__ == "__main__":
    # สำหรับรันทดสอบในเครื่องเท่านั้น; Render ควรใช้ Gunicorn
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
