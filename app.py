"""Secure authentication demo (Flask).

Implements defensive authentication controls:
  1. Password hashing + server-side input validation
  2. Secure cookie settings, logout, and session expiry
  3. Rate limits and generic authentication errors
"""
import os
import re
import secrets
import sqlite3
import time

from flask import Flask, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,}$")
SESSION_LIFETIME_SECONDS = 15 * 60       # session expiry: 15 minutes
MAX_FAILED_ATTEMPTS = 5                  # per (ip, email) window
RATE_WINDOW_SECONDS = 5 * 60

GENERIC_LOGIN_ERROR = "Invalid email or password."
GENERIC_REGISTER_ERROR = "Registration could not be completed."

# Hash used to keep response time similar when the email does not exist.
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


def now():
    """Current time in seconds. Isolated so tests can control the clock."""
    return time.time()


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        # Never hard-code a real secret. Set SECRET_KEY in the environment.
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=os.environ.get("DATABASE", "users.db"),
        SESSION_COOKIE_NAME="session",
        SESSION_COOKIE_HTTPONLY=True,     # JavaScript cannot read the cookie
        SESSION_COOKIE_SECURE=True,       # only sent over HTTPS
        SESSION_COOKIE_SAMESITE="Lax",    # basic CSRF protection
        MAX_CONTENT_LENGTH=16 * 1024,     # reject huge request bodies
    )
    if config:
        app.config.update(config)

    app.failed_attempts = {}              # {(ip, email): [timestamps]}

    # ---------- database ----------
    def db():
        conn = sqlite3.connect(app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        return conn

    with db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "email TEXT UNIQUE NOT NULL,"
            "password_hash TEXT NOT NULL)"
        )

    # ---------- helpers ----------
    def validate_credentials(data):
        if not isinstance(data, dict):
            return None, None, "Invalid request."
        email, password = data.get("email"), data.get("password")
        if not isinstance(email, str) or not isinstance(password, str):
            return None, None, "Invalid request."
        email = email.strip().lower()
        if not EMAIL_RE.match(email):
            return None, None, "Invalid email format."
        if not (10 <= len(password) <= 128):
            return None, None, "Password must be 10 to 128 characters."
        if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
            return None, None, "Password must contain letters and numbers."
        return email, password, None

    def recent_failures(key):
        cutoff = now() - RATE_WINDOW_SECONDS
        app.failed_attempts[key] = [t for t in app.failed_attempts.get(key, []) if t > cutoff]
        return app.failed_attempts[key]

    @app.after_request
    def security_headers(resp):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

    # ---------- routes ----------
    @app.post("/register")
    def register():
        email, password, error = validate_credentials(request.get_json(silent=True))
        if error:
            return jsonify(error=error), 400
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, generate_password_hash(password)),
                )
        except sqlite3.IntegrityError:
            # Same message as other failures: do not reveal that the email exists.
            return jsonify(error=GENERIC_REGISTER_ERROR), 400
        return jsonify(message="Registered."), 201

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict) or not isinstance(data.get("email"), str) \
                or not isinstance(data.get("password"), str):
            return jsonify(error=GENERIC_LOGIN_ERROR), 401
        email = data["email"].strip().lower()
        key = (request.remote_addr, email)

        if len(recent_failures(key)) >= MAX_FAILED_ATTEMPTS:
            return jsonify(error="Too many attempts. Try again later."), 429

        with db() as conn:
            row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        stored = row["password_hash"] if row else _DUMMY_HASH
        ok = check_password_hash(stored, data["password"]) and row is not None

        if not ok:
            app.failed_attempts[key].append(now())
            return jsonify(error=GENERIC_LOGIN_ERROR), 401  # same for unknown email / wrong password

        app.failed_attempts.pop(key, None)
        session.clear()                    # prevent session fixation
        session["user_id"] = row["id"]
        session["issued_at"] = now()
        session.permanent = True
        return jsonify(message="Logged in."), 200

    @app.post("/logout")
    def logout():
        session.clear()
        return jsonify(message="Logged out."), 200

    @app.get("/profile")
    def profile():
        user_id, issued = session.get("user_id"), session.get("issued_at")
        if user_id is None or issued is None:
            return jsonify(error="Authentication required."), 401
        if now() - issued > SESSION_LIFETIME_SECONDS:   # server-side expiry check
            session.clear()
            return jsonify(error="Session expired."), 401
        with db() as conn:
            row = conn.execute("SELECT email FROM users WHERE id = ?", (user_id,)).fetchone()
        if row is None:
            session.clear()
            return jsonify(error="Authentication required."), 401
        return jsonify(email=row["email"]), 200

    app.permanent_session_lifetime = SESSION_LIFETIME_SECONDS
    return app


if __name__ == "__main__":
    # Development only. In production run behind HTTPS with a real WSGI server.
    create_app({"SESSION_COOKIE_SECURE": False}).run(debug=False)
