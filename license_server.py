import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, render_template_string, send_file

app = Flask(__name__)

DB_PATH = Path(__file__).parent / "licenses.db"
SERVER_API_KEY = os.environ.get("SERVER_API_KEY", "CHANGE_ME_SECRET_KEY_2026")

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
        key = request.headers.get("X-API-Key", "")
        if key != SERVER_API_KEY:
            return jsonify({"status": "forbidden", "message": "Invalid API key"}), 403
        return f(*args, **kwargs)
    return decorated

def hash_hwid(hwid: str) -> str:
    return hashlib.sha256(hwid.encode()).hexdigest()

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "WarZ License API"}), 200

@app.route("/check", methods=["POST"])
@require_api_key
def check_license():
    data = request.get_json(silent=True) or {}
    license_key = str(data.get("license_key", "")).strip()
    hwid_raw    = str(data.get("hwid", "")).strip()

    if not license_key or not hwid_raw:
        return jsonify({"status": "invalid", "message": "Missing fields"}), 400

    hwid_hash = hash_hwid(hwid_raw)

    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM licenses WHERE license_key = ?", (license_key,)
        ).fetchone()

        if not row:
            return jsonify({"status": "invalid", "message": "License key not found"}), 200

        if not row["is_active"]:
            return jsonify({"status": "invalid", "message": "License is disabled"}), 200

        try:
            expire_dt = datetime.fromisoformat(row["expire_date"])
            if expire_dt.tzinfo is None:
                expire_dt = expire_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expire_dt:
                return jsonify({
                    "status": "expired",
                    "message": f"License expired on {row['expire_date']}",
                    "expire_date": row["expire_date"],
                }), 200
        except ValueError:
            return jsonify({"status": "invalid", "message": "Invalid expire_date in DB"}), 200

        if not row["hwid_bound"]:
            conn.execute(
                "UPDATE licenses SET hwid_bound = ?, last_seen = ? WHERE license_key = ?",
                (hwid_hash, now_utc(), license_key),
            )
            conn.commit()
        else:
            if row["hwid_bound"] != hwid_hash:
                return jsonify({
                    "status": "hwid_mismatch",
                    "message": "License is bound to a different machine",
                }), 200
            conn.execute(
                "UPDATE licenses SET last_seen = ? WHERE license_key = ?",
                (now_utc(), license_key),
            )
            conn.commit()

    return jsonify({
        "status": "valid",
        "message": "License OK",
        "expire_date": row["expire_date"],
    }), 200

@app.route("/admin/add", methods=["POST"])
@require_api_key
def admin_add():
    data = request.get_json(silent=True) or {}
    key         = str(data.get("license_key", "")).strip()
    expire_date = str(data.get("expire_date", "")).strip()
    note        = str(data.get("note", "")).strip()

    if not key or not expire_date:
        return jsonify({"status": "error", "message": "license_key and expire_date required"}), 400

    try:
        datetime.fromisoformat(expire_date)
    except ValueError:
        return jsonify({"status": "error", "message": "expire_date format: YYYY-MM-DD"}), 400

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO licenses (license_key, expire_date, note) VALUES (?, ?, ?)",
                (key, expire_date, note),
            )
            conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "message": "license_key already exists"}), 409

    return jsonify({"status": "ok", "message": f"Added {key} expires {expire_date}"}), 201


@app.route("/admin", methods=["GET"])
def admin_dashboard():
    admin_file = Path(__file__).parent / "admin.html"

    if not admin_file.exists():
        return "admin.html not found", 404

    return send_file(admin_file)
