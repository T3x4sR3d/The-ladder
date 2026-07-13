from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, flash, g, make_response, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "ladder.db"

GRADE_ORDER = {"Master": 1, "A": 2, "B": 3, "C": 4, "D": 5}
GRADES = ["D", "C", "B", "A", "Master"]
SEX_OPTIONS = ["Male", "Female", "Other"]
AUTO_PROCESS_INTERVAL_SECONDS = 60
INNER_WEIGHT = 0.15

# For the proof-of-concept this is local. Before real deployment, set LADDER_SECRET_KEY
# to a long random value and keep it private.
app = Flask(__name__)
app.secret_key = os.environ.get("LADDER_SECRET_KEY", "dev-change-this-secret-key-before-real-use")
USERNAME_PEPPER = os.environ.get("LADDER_USERNAME_PEPPER", app.secret_key)

# Simple in-memory protections for the proof-of-concept.
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
REQUEST_LOG: dict[str, list[float]] = {}
BLOCKED_UA_PARTS = [
    "sqlmap", "nikto", "acunetix", "nessus", "nmap", "masscan", "zgrab",
    "python-requests", "scrapy", "curl", "wget", "httpclient", "libwww",
]

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,40}$")
TSNZ_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,30}$")
NAME_RE = re.compile(r"^[A-Za-zĀ-ž' -]{1,80}$")


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def normalize_username(username: str) -> str:
    return username.strip().lower()


def username_hash(username: str, salt: str) -> str:
    normalized = normalize_username(username)
    return hmac.new(
        f"{USERNAME_PEPPER}:{salt}".encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def make_username_record(username: str) -> tuple[str, str]:
    if not USERNAME_RE.fullmatch(username.strip()):
        raise ValueError("Username must be 3-40 characters and use only letters, numbers, dots, dashes, or underscores.")
    salt = secrets.token_hex(16)
    return salt, username_hash(username, salt)


def find_club_by_username(conn: sqlite3.Connection, username: str):
    normalized = normalize_username(username)
    if not USERNAME_RE.fullmatch(normalized):
        return None
    # Usernames are not stored in plain text. For this small club system we scan
    # the club rows and compare HMAC hashes using each row's salt.
    for club in conn.execute("SELECT * FROM clubs").fetchall():
        expected = username_hash(normalized, club["username_salt"])
        if hmac.compare_digest(expected, club["username_hash"]):
            return club
    return None


def find_shooter_by_tsnz(conn: sqlite3.Connection, tsnz_number: str):
    tsnz_number = tsnz_number.strip()
    if not TSNZ_RE.fullmatch(tsnz_number):
        return None
    return conn.execute(
        """
        SELECT shooters.*, clubs.name AS club_name
        FROM shooters
        JOIN clubs ON clubs.id = shooters.club_id
        WHERE shooters.tsnz_number = ? AND shooters.active = 1
        """,
        (tsnz_number,),
    ).fetchone()


def get_client_ip() -> str:
    # For local/Raspberry Pi use. Behind a reverse proxy, configure trusted proxy handling later.
    return request.remote_addr or "unknown"


def too_many_recent_hits(bucket: dict[str, list[float]], key: str, limit: int, window_seconds: int) -> bool:
    now = time.time()
    hits = [t for t in bucket.get(key, []) if now - t < window_seconds]
    bucket[key] = hits
    return len(hits) >= limit


def record_hit(bucket: dict[str, list[float]], key: str) -> None:
    bucket.setdefault(key, []).append(time.time())


def get_week_start(today: date | None = None) -> date:
    today = today or date.today()
    return today - timedelta(days=today.weekday())


def get_week_end(today: date | None = None) -> date:
    return get_week_start(today) + timedelta(days=6)


def display_date(value: str | date | None) -> str:
    if not value:
        return "-"
    if isinstance(value, date):
        return value.strftime("%d/%m/%Y")
    try:
        return datetime.strptime(value, "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return value


def parse_dob(dob_text: str) -> str:
    try:
        return datetime.strptime(dob_text.strip(), "%d/%m/%Y").date().isoformat()
    except ValueError:
        raise ValueError("DOB must be in day/month/year format, e.g. 24/09/2004")


def age_status_from_dob(dob_iso: str, year: int | None = None) -> str:
    year = year or date.today().year
    dob = datetime.strptime(dob_iso, "%Y-%m-%d").date()
    turns_21_this_year = date(dob.year + 21, dob.month, dob.day)
    if turns_21_this_year.year > year:
        return "Junior"
    turns_60_this_year = date(dob.year + 60, dob.month, dob.day)
    if turns_60_this_year.year <= year:
        return "Veteran"
    return "Standard"


def get_default_attack_parity(for_date: date | None = None) -> str:
    # Week 1 = even positions attack. Week 2 = odd positions attack.
    for_date = for_date or date.today()
    week_number = for_date.isocalendar().week
    return "even" if week_number % 2 == 1 else "odd"


def get_attack_parity(for_date: date | None = None) -> str:
    """Return the attack parity for a week, allowing super-admin weekly overrides."""
    for_date = for_date or date.today()
    week_start = get_week_start(for_date).isoformat()
    try:
        with db() as conn:
            row = conn.execute(
                "SELECT attack_parity FROM week_settings WHERE week_start = ?",
                (week_start,),
            ).fetchone()
        if row and row["attack_parity"] in {"odd", "even"}:
            return row["attack_parity"]
    except sqlite3.Error:
        # Database may not exist yet during first startup. Fall back to the normal pattern.
        pass
    return get_default_attack_parity(for_date)


def describe_attack_parity(parity: str) -> tuple[str, str]:
    if parity == "even":
        return "Even positions attack", "Odd positions defend"
    return "Odd positions attack", "Even positions defend"


def get_app_setting(key: str, default: str = "") -> str:
    try:
        with db() as conn:
            row = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    except sqlite3.Error:
        return default


def set_app_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO app_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (key, value, datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()


def national_ladder_enabled() -> bool:
    return get_app_setting("national_ladder_enabled", "0") == "1"


def score_to_points(score_text: str) -> int:
    raw = score_text.strip()
    if not re.fullmatch(r"\d{1,3}(\.\d{1,2})?", raw):
        raise ValueError("Score must look like 98.07, 100.10, or 97")

    if "." not in raw:
        whole_text = raw
        inner_text = "00"
    else:
        whole_text, inner_text = raw.split(".", 1)

    whole = int(whole_text)
    inner = int(inner_text)

    if whole < 0 or whole > 100:
        raise ValueError("Main score must be between 0 and 100")
    if inner < 0 or inner > 10:
        raise ValueError("Inner score must be between .00 and .10")
    if inner == 10 and whole != 100:
        raise ValueError("Only 100 can have .10")
    if inner > 0 and whole < inner * 10:
        raise ValueError(f"A score with .{inner:02d} must be at least {inner * 10}.{inner:02d}")

    return whole * 100 + inner


def format_score(score_points: int | None) -> str:
    if score_points is None:
        return "-"
    return f"{score_points // 100}.{score_points % 100:02d}"


def validate_plain_text(value: str, label: str, pattern: re.Pattern, max_len: int = 80) -> str:
    value = value.strip()
    if not value or len(value) > max_len or not pattern.fullmatch(value):
        raise ValueError(f"Invalid {label}.")
    return value


@app.template_filter("dmy")
def dmy_filter(value):
    return display_date(value)


@app.template_filter("score")
def score_filter(value):
    return format_score(value)


@app.template_filter("age_status")
def age_status_filter(value):
    try:
        return age_status_from_dob(value)
    except Exception:
        return "-"

@app.template_filter("weighted")
def weighted_filter(value):
    if value is None:
        return "-"
    return f"{float(value):.2f}"


def score_parts(score_points: int) -> tuple[int, int]:
    return score_points // 100, score_points % 100


def weighted_score_points(score_points: int) -> float:
    whole, inner = score_parts(score_points)
    return whole + (inner * INNER_WEIGHT)


def format_average_score(avg_points: float | None) -> str:
    if avg_points is None:
        return "-"
    return f"{avg_points / 100:.2f}"


def get_rankings(filters: dict | None = None):
    filters = filters or {}
    where = ["shooters.active = 1"]
    params = []
    if filters.get("grade"):
        where.append("shooters.grade = ?")
        params.append(filters["grade"])
    if filters.get("sex"):
        where.append("shooters.sex = ?")
        params.append(filters["sex"])
    if filters.get("age_status"):
        # Age status is calculated in Python, so apply this after fetching.
        pass
    if filters.get("club_id"):
        where.append("shooters.club_id = ?")
        params.append(filters["club_id"])

    sql = f"""
        SELECT shooters.*, clubs.name AS club_name,
               COUNT(ranking_scores.id) AS event_count,
               AVG(ranking_scores.score_points) AS avg_score_points,
               AVG((ranking_scores.score_points / 100) + ((ranking_scores.score_points % 100) * ?)) AS weighted_score
        FROM shooters
        JOIN clubs ON clubs.id = shooters.club_id
        LEFT JOIN ranking_scores ON ranking_scores.shooter_id = shooters.id
        WHERE {' AND '.join(where)}
        GROUP BY shooters.id
        ORDER BY
            CASE WHEN event_count = 0 THEN 1 ELSE 0 END ASC,
            weighted_score DESC,
            avg_score_points DESC,
            shooters.surname COLLATE NOCASE ASC,
            shooters.first_name COLLATE NOCASE ASC
    """
    with db() as conn:
        rows = [dict(r) for r in conn.execute(sql, [INNER_WEIGHT] + params).fetchall()]

    if filters.get("age_status"):
        rows = [r for r in rows if age_status_from_dob(r["dob"]) == filters["age_status"]]

    for idx, row in enumerate(rows, start=1):
        row["rank"] = idx
        row["age_status"] = age_status_from_dob(row["dob"])
        row["avg_score_display"] = format_average_score(row["avg_score_points"])
        row["weighted_score_display"] = format_average_score(row["weighted_score"] * 100) if row["weighted_score"] is not None else "-"
    return rows


def get_ranking_score_history(shooter_id: int | None = None, limit: int | None = None):
    sql = """
        SELECT ranking_scores.*, shooters.tsnz_number, shooters.first_name, shooters.surname,
               clubs.name AS club_name
        FROM ranking_scores
        JOIN shooters ON shooters.id = ranking_scores.shooter_id
        JOIN clubs ON clubs.id = shooters.club_id
    """
    params = []
    if shooter_id is not None:
        sql += " WHERE ranking_scores.shooter_id = ?"
        params.append(shooter_id)
    sql += " ORDER BY ranking_scores.event_date DESC, ranking_scores.entered_at DESC"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    with db() as conn:
        return conn.execute(sql, params).fetchall()


def migrate_legacy_clubs_table(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clubs'").fetchall()
    if not rows:
        return

    columns = [row["name"] for row in conn.execute("PRAGMA table_info(clubs)").fetchall()]
    if "username_hash" in columns and "username_salt" in columns and "username" not in columns:
        return

    conn.execute("PRAGMA foreign_keys = OFF")
    old_rows = conn.execute("SELECT * FROM clubs").fetchall()
    conn.execute("ALTER TABLE clubs RENAME TO clubs_legacy")
    conn.execute(
        """
        CREATE TABLE clubs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            username_salt TEXT NOT NULL,
            username_hash TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_super INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    for row in old_rows:
        old_username = row["username"] if "username" in row.keys() else f"club{row['id']}"
        salt, uhash = make_username_record(old_username)
        conn.execute(
            "INSERT INTO clubs (id, name, username_salt, username_hash, password_hash, is_super) VALUES (?, ?, ?, ?, ?, ?)",
            (row["id"], row["name"], salt, uhash, row["password_hash"], row["is_super"]),
        )
    conn.execute("DROP TABLE clubs_legacy")
    conn.execute("PRAGMA foreign_keys = ON")


def create_club_if_missing(conn: sqlite3.Connection, name: str, username: str, password: str, is_super: int = 0) -> None:
    existing = conn.execute("SELECT id FROM clubs WHERE name = ?", (name,)).fetchone()
    if existing:
        return
    salt, uhash = make_username_record(username)
    conn.execute(
        "INSERT INTO clubs (name, username_salt, username_hash, password_hash, is_super) VALUES (?, ?, ?, ?, ?)",
        (name, salt, uhash, generate_password_hash(password), is_super),
    )


def init_db() -> None:
    with db() as conn:
        migrate_legacy_clubs_table(conn)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS clubs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                username_salt TEXT NOT NULL,
                username_hash TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_super INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS shooters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tsnz_number TEXT NOT NULL UNIQUE,
                first_name TEXT NOT NULL,
                surname TEXT NOT NULL,
                dob TEXT NOT NULL,
                sex TEXT NOT NULL,
                grade TEXT NOT NULL,
                club_id INTEGER NOT NULL,
                ladder_position INTEGER NOT NULL,
                club_ladder_position INTEGER NOT NULL DEFAULT 1,
                shooter_password_hash TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (club_id) REFERENCES clubs(id)
            );

            CREATE TABLE IF NOT EXISTS scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                shooter_id INTEGER NOT NULL,
                club_id INTEGER NOT NULL,
                week_start TEXT NOT NULL,
                score_points INTEGER NOT NULL,
                result TEXT,
                club_result TEXT,
                entered_at TEXT NOT NULL,
                UNIQUE(shooter_id, week_start),
                FOREIGN KEY (shooter_id) REFERENCES shooters(id),
                FOREIGN KEY (club_id) REFERENCES clubs(id)
            );

            CREATE TABLE IF NOT EXISTS ranking_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                shooter_id INTEGER NOT NULL,
                event_name TEXT NOT NULL,
                event_date TEXT NOT NULL,
                score_points INTEGER NOT NULL,
                notes TEXT,
                entered_by INTEGER,
                entered_at TEXT NOT NULL,
                FOREIGN KEY (shooter_id) REFERENCES shooters(id),
                FOREIGN KEY (entered_by) REFERENCES clubs(id)
            );

            CREATE TABLE IF NOT EXISTS processed_weeks (
                week_start TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL,
                attack_parity TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS week_settings (
                week_start TEXT PRIMARY KEY,
                attack_parity TEXT NOT NULL CHECK (attack_parity IN ('odd', 'even')),
                updated_at TEXT NOT NULL,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES clubs(id)
            );

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )

        # Lightweight migrations for databases created by earlier proof-of-concept versions.
        shooter_columns = [row["name"] for row in conn.execute("PRAGMA table_info(shooters)").fetchall()]
        if "club_ladder_position" not in shooter_columns:
            conn.execute("ALTER TABLE shooters ADD COLUMN club_ladder_position INTEGER NOT NULL DEFAULT 1")
            for club in conn.execute("SELECT id FROM clubs WHERE is_super = 0").fetchall():
                normalize_club_positions(conn, club["id"])
        if "shooter_password_hash" not in shooter_columns:
            conn.execute("ALTER TABLE shooters ADD COLUMN shooter_password_hash TEXT")

        score_columns = [row["name"] for row in conn.execute("PRAGMA table_info(scores)").fetchall()]
        if "club_result" not in score_columns:
            conn.execute("ALTER TABLE scores ADD COLUMN club_result TEXT")

        create_club_if_missing(conn, "Super User", "superadmin", "change-me-now", 1)
        conn.execute(
            "INSERT OR IGNORE INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)",
            ("national_ladder_enabled", "0", datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()


def current_user():
    if session.get("account_type") != "club":
        return None
    user_id = session.get("user_id")
    if not user_id:
        return None
    with db() as conn:
        return conn.execute("SELECT * FROM clubs WHERE id = ?", (user_id,)).fetchone()


def current_shooter():
    if session.get("account_type") != "shooter":
        return None
    shooter_id = session.get("shooter_id")
    if not shooter_id:
        return None
    with db() as conn:
        return conn.execute(
            """
            SELECT shooters.*, clubs.name AS club_name
            FROM shooters JOIN clubs ON clubs.id = shooters.club_id
            WHERE shooters.id = ? AND shooters.active = 1
            """,
            (shooter_id,),
        ).fetchone()


def logged_in() -> bool:
    return session.get("account_type") in {"club", "shooter"}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not logged_in():
            flash("Please log in first.", "error")
            return redirect("/login")
        return view(*args, **kwargs)
    return wrapped


def club_admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not logged_in():
            flash("Please log in first.", "error")
            return redirect("/login")
        if session.get("account_type") != "club":
            flash("Shooter accounts can view ladders only.", "error")
            return redirect("/")
        return view(*args, **kwargs)
    return wrapped


def super_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        u = current_user()
        if not u:
            flash("Please log in first.", "error")
            return redirect("/login")
        if not u["is_super"]:
            flash("Super-user access required.", "error")
            return redirect("/club")
        return view(*args, **kwargs)
    return wrapped


@app.context_processor
def inject_template_vars():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    current_attack_parity = get_attack_parity()
    attack_text, defend_text = describe_attack_parity(current_attack_parity)
    return {
        "csrf_token": session["csrf_token"],
        "attack_parity": current_attack_parity,
        "attack_text": attack_text,
        "defend_text": defend_text,
        "national_ladder_enabled": national_ladder_enabled(),
        "week_start": get_week_start(),
        "week_end": get_week_end(),
    }


@app.before_request
def security_checks_and_auto_processing():
    ip = get_client_ip()
    ua = (request.headers.get("User-Agent") or "").lower()

    if any(part in ua for part in BLOCKED_UA_PARTS):
        return make_response("Forbidden", 403)

    record_hit(REQUEST_LOG, ip)
    if too_many_recent_hits(REQUEST_LOG, ip, limit=300, window_seconds=60):
        return make_response("Too many requests", 429)

    if request.method == "POST":
        sent_token = request.form.get("csrf_token", "")
        expected_token = session.get("csrf_token", "")
        if not expected_token or not hmac.compare_digest(sent_token, expected_token):
            return make_response("Bad CSRF token", 400)

    # Auto-process due weeks while the app is running or when it is opened after downtime.
    if request.endpoint not in {"static"}:
        auto_process_due_weeks()


@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


def pair_info_for_position(position: int, ladder_size: int, attack: str) -> tuple[int | None, str, int | None]:
    """Return pair group, role, and opponent position for the current weekly challenge."""
    if attack == "even":
        if position % 2 == 0:
            return position // 2, "attacker", position - 1
        if position + 1 <= ladder_size:
            return (position + 1) // 2, "defender", position + 1
        return None, "bye", None

    # Odd positions attack the shooter immediately above them. Position 1 has no one above it.
    if position == 1:
        return None, "bye", None
    if position % 2 == 1:
        return (position - 1) // 2, "attacker", position - 1
    if position + 1 <= ladder_size:
        return position // 2, "defender", position + 1
    return None, "bye", None


def get_ladder(club_id: int | None = None):
    week = get_week_start().isoformat()
    attack = get_attack_parity()
    result_column = "scores.club_result" if club_id is not None else "scores.result"
    position_column = "shooters.club_ladder_position" if club_id is not None else "shooters.ladder_position"
    sql = f"""
        SELECT shooters.*, clubs.name AS club_name,
               {position_column} AS display_position,
               scores.score_points AS current_score,
               {result_column} AS result
        FROM shooters
        JOIN clubs ON clubs.id = shooters.club_id
        LEFT JOIN scores ON scores.shooter_id = shooters.id AND scores.week_start = ?
        WHERE shooters.active = 1
    """
    params: list = [week]
    if club_id is not None:
        sql += " AND shooters.club_id = ?"
        params.append(club_id)
    sql += f" ORDER BY {position_column} ASC"
    with db() as conn:
        rows = [dict(r) for r in conn.execute(sql, params).fetchall()]

    ladder_size = len(rows)
    by_position = {row["display_position"]: row for row in rows}

    for row in rows:
        pair_group, role, opponent_position = pair_info_for_position(row["display_position"], ladder_size, attack)
        row["pair_group"] = pair_group
        row["challenge_role"] = role
        row["opponent_position"] = opponent_position
        opponent = by_position.get(opponent_position) if opponent_position else None
        row["opponent_name"] = f"{opponent['first_name']} {opponent['surname']}" if opponent else ""

        if opponent and row.get("current_score") is not None and opponent.get("current_score") is None:
            row["display_score"] = "Hidden until opponent enters score"
            row["score_hidden"] = True
        elif opponent and row.get("current_score") is None:
            row["display_score"] = "Not entered"
            row["score_hidden"] = False
        else:
            row["display_score"] = format_score(row.get("current_score"))
            row["score_hidden"] = False

    return rows


def next_ladder_position() -> int:
    with db() as conn:
        row = conn.execute("SELECT COALESCE(MAX(ladder_position), 0) + 1 AS next_pos FROM shooters").fetchone()
    return int(row["next_pos"])


def next_club_ladder_position(club_id: int) -> int:
    with db() as conn:
        row = conn.execute(
            "SELECT COALESCE(MAX(club_ladder_position), 0) + 1 AS next_pos FROM shooters WHERE club_id = ?",
            (club_id,),
        ).fetchone()
    return int(row["next_pos"])


def normalize_global_positions(conn: sqlite3.Connection) -> None:
    rows = conn.execute("SELECT id FROM shooters WHERE active = 1 ORDER BY ladder_position, surname, first_name").fetchall()
    for idx, shooter in enumerate(rows, start=1):
        conn.execute("UPDATE shooters SET ladder_position = ? WHERE id = ?", (idx, shooter["id"]))


def normalize_club_positions(conn: sqlite3.Connection, club_id: int) -> None:
    rows = conn.execute(
        "SELECT id FROM shooters WHERE active = 1 AND club_id = ? ORDER BY club_ladder_position, surname, first_name",
        (club_id,),
    ).fetchall()
    for idx, shooter in enumerate(rows, start=1):
        conn.execute("UPDATE shooters SET club_ladder_position = ? WHERE id = ?", (idx, shooter["id"]))


def reorder_by_grade() -> None:
    with db() as conn:
        rows = conn.execute("SELECT * FROM shooters WHERE active = 1").fetchall()
        sorted_rows = sorted(rows, key=lambda r: (GRADE_ORDER.get(r["grade"], 99), r["ladder_position"], r["surname"].lower()))
        for idx, shooter in enumerate(sorted_rows, start=1):
            conn.execute("UPDATE shooters SET ladder_position = ? WHERE id = ?", (idx, shooter["id"]))
        # Keep each club ladder neat, but do not reorder the club ladder by grade.
        club_rows = conn.execute("SELECT id FROM clubs WHERE is_super = 0").fetchall()
        for club in club_rows:
            normalize_club_positions(conn, club["id"])
        conn.commit()


def swap_global_position(shooter_id: int, direction: str) -> bool:
    with db() as conn:
        shooter = conn.execute("SELECT * FROM shooters WHERE id = ? AND active = 1", (shooter_id,)).fetchone()
        if not shooter:
            return False
        op = "<" if direction == "up" else ">"
        order = "DESC" if direction == "up" else "ASC"
        other = conn.execute(
            f"SELECT * FROM shooters WHERE active = 1 AND ladder_position {op} ? ORDER BY ladder_position {order} LIMIT 1",
            (shooter["ladder_position"],),
        ).fetchone()
        if not other:
            return False
        conn.execute("UPDATE shooters SET ladder_position = ? WHERE id = ?", (other["ladder_position"], shooter["id"]))
        conn.execute("UPDATE shooters SET ladder_position = ? WHERE id = ?", (shooter["ladder_position"], other["id"]))
        conn.commit()
        return True


def swap_club_position(shooter_id: int, direction: str, allowed_club_id: int | None = None) -> bool:
    with db() as conn:
        shooter = conn.execute("SELECT * FROM shooters WHERE id = ? AND active = 1", (shooter_id,)).fetchone()
        if not shooter:
            return False
        if allowed_club_id is not None and shooter["club_id"] != allowed_club_id:
            return False
        op = "<" if direction == "up" else ">"
        order = "DESC" if direction == "up" else "ASC"
        other = conn.execute(
            f"""
            SELECT * FROM shooters
            WHERE active = 1 AND club_id = ? AND club_ladder_position {op} ?
            ORDER BY club_ladder_position {order}
            LIMIT 1
            """,
            (shooter["club_id"], shooter["club_ladder_position"]),
        ).fetchone()
        if not other:
            return False
        conn.execute("UPDATE shooters SET club_ladder_position = ? WHERE id = ?", (other["club_ladder_position"], shooter["id"]))
        conn.execute("UPDATE shooters SET club_ladder_position = ? WHERE id = ?", (shooter["club_ladder_position"], other["id"]))
        conn.commit()
        return True


@app.route("/robots.txt")
def robots_txt():
    response = make_response("User-agent: *\nDisallow: /\n")
    response.headers["Content-Type"] = "text/plain"
    return response


@app.route("/")
@login_required
def index():
    filters = {
        "grade": request.args.get("grade", "").strip(),
        "sex": request.args.get("sex", "").strip(),
        "age_status": request.args.get("age_status", "").strip(),
        "club_id": request.args.get("club_id", "").strip(),
    }
    if filters["grade"] not in GRADES:
        filters["grade"] = ""
    if filters["sex"] not in SEX_OPTIONS:
        filters["sex"] = ""
    if filters["age_status"] not in {"Junior", "Standard", "Veteran"}:
        filters["age_status"] = ""
    if filters["club_id"]:
        try:
            filters["club_id"] = int(filters["club_id"])
        except ValueError:
            filters["club_id"] = ""
    with db() as conn:
        clubs = conn.execute("SELECT id, name FROM clubs WHERE is_super = 0 ORDER BY name").fetchall()
    shooter = current_shooter()
    shooter_rank_history = get_ranking_score_history(shooter["id"]) if shooter else []
    return render_template(
        "rankings.html",
        title="New Zealand Rankings",
        rankings=get_rankings(filters),
        filters=filters,
        grades=GRADES,
        sex_options=SEX_OPTIONS,
        clubs=clubs,
        user=current_user(),
        shooter=shooter,
        shooter_rank_history=shooter_rank_history,
    )


@app.route("/national-ladder")
@login_required
def national_ladder():
    if not national_ladder_enabled():
        flash("The New Zealand Ladder is currently turned off.", "error")
        return redirect("/")
    return render_template(
        "index.html",
        title="New Zealand Ladder",
        ladder=get_ladder(None),
        user=current_user(),
        shooter=current_shooter(),
    )


@app.route("/club")
@login_required
def club_ladder():
    if session.get("account_type") == "shooter":
        shooter = current_shooter()
        if not shooter:
            flash("Please log in first.", "error")
            return redirect("/login")
        return render_template("index.html", title="Club Ladder", ladder=get_ladder(shooter["club_id"]), user=None, shooter=shooter)

    u = current_user()
    if u["is_super"]:
        return redirect("/admin")
    return render_template("index.html", title="Club Ladder", ladder=get_ladder(u["id"]), user=u, shooter=None)




@app.route("/rules")
@login_required
def rules():
    return render_template("rules.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if logged_in() and request.method == "GET":
        if session.get("account_type") == "club":
            return redirect("/admin" if session.get("is_super") else "/club")
        return redirect("/")

    if request.method == "POST":
        ip = get_client_ip()
        record_hit(LOGIN_ATTEMPTS, ip)
        if too_many_recent_hits(LOGIN_ATTEMPTS, ip, limit=8, window_seconds=15 * 60):
            flash("Too many login attempts. Try again later.", "error")
            return render_template("login.html", user=current_user())

        # Honeypot field. Real users should leave it empty.
        if request.form.get("website", "").strip():
            time.sleep(1)
            flash("Invalid login.", "error")
            return render_template("login.html", user=current_user())

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            u = find_club_by_username(conn, username)
            shooter = None if u else find_shooter_by_tsnz(conn, username)

        # Use one generic error message to avoid account enumeration.
        if u and check_password_hash(u["password_hash"], password):
            session.clear()
            session["account_type"] = "club"
            session["user_id"] = u["id"]
            session["is_super"] = bool(u["is_super"])
            session["csrf_token"] = secrets.token_urlsafe(32)
            flash("Logged in successfully.", "success")
            return redirect("/admin" if u["is_super"] else "/club")

        if shooter and shooter["shooter_password_hash"] and check_password_hash(shooter["shooter_password_hash"], password):
            session.clear()
            session["account_type"] = "shooter"
            session["shooter_id"] = shooter["id"]
            session["club_id"] = shooter["club_id"]
            session["is_super"] = False
            session["csrf_token"] = secrets.token_urlsafe(32)
            flash("Logged in successfully.", "success")
            return redirect("/")
        time.sleep(0.6)
        flash("Invalid username or password.", "error")
    return render_template("login.html", user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "success")
    return redirect("/login")


@app.route("/admin")
@club_admin_required
def admin():
    u = current_user()
    with db() as conn:
        clubs = conn.execute("SELECT id, name, is_super FROM clubs ORDER BY name").fetchall() if u["is_super"] else []
        shooters = conn.execute(
            """
            SELECT shooters.*, clubs.name AS club_name
            FROM shooters JOIN clubs ON clubs.id = shooters.club_id
            WHERE shooters.active = 1
            ORDER BY clubs.name, shooters.club_ladder_position
            """
        ).fetchall() if u["is_super"] else conn.execute(
            """
            SELECT shooters.*, clubs.name AS club_name
            FROM shooters JOIN clubs ON clubs.id = shooters.club_id
            WHERE shooters.active = 1 AND shooters.club_id = ?
            ORDER BY shooters.club_ladder_position
            """,
            (u["id"],),
        ).fetchall()
        recent_scores = conn.execute(
            """
            SELECT scores.*, shooters.tsnz_number, shooters.first_name, shooters.surname, clubs.name AS club_name
            FROM scores
            JOIN shooters ON shooters.id = scores.shooter_id
            JOIN clubs ON clubs.id = scores.club_id
            ORDER BY scores.entered_at DESC
            LIMIT 30
            """
        ).fetchall() if u["is_super"] else conn.execute(
            """
            SELECT scores.*, shooters.tsnz_number, shooters.first_name, shooters.surname, clubs.name AS club_name
            FROM scores
            JOIN shooters ON shooters.id = scores.shooter_id
            JOIN clubs ON clubs.id = scores.club_id
            WHERE scores.club_id = ?
            ORDER BY scores.entered_at DESC
            LIMIT 30
            """,
            (u["id"],),
        ).fetchall()
        recent_ranking_scores = get_ranking_score_history(limit=50) if u["is_super"] else []
    current_attack = get_attack_parity()
    default_attack = get_default_attack_parity()
    return render_template(
        "admin.html",
        user=u,
        clubs=clubs,
        shooters=shooters,
        recent_scores=recent_scores,
        recent_ranking_scores=recent_ranking_scores,
        grades=GRADES,
        sex_options=SEX_OPTIONS,
        current_attack=current_attack,
        default_attack=default_attack,
        national_ladder_enabled=national_ladder_enabled(),
    )


@app.route("/change_super_password", methods=["POST"])
@super_required
def change_super_password():
    u = current_user()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not check_password_hash(u["password_hash"], current_password):
        flash("Current super admin password is incorrect.", "error")
        return redirect("/admin")

    if len(new_password) < 10:
        flash("New super admin password must be at least 10 characters.", "error")
        return redirect("/admin")

    if new_password != confirm_password:
        flash("New password and confirmation do not match.", "error")
        return redirect("/admin")

    with db() as conn:
        conn.execute(
            "UPDATE clubs SET password_hash = ? WHERE id = ? AND is_super = 1",
            (generate_password_hash(new_password), u["id"]),
        )
        conn.commit()

    flash("Super admin password updated.", "success")
    return redirect("/admin")


@app.route("/add_club", methods=["POST"])
@super_required
def add_club():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    if not name or not username or not password:
        flash("Club name, username, and password are required.", "error")
        return redirect("/admin")
    if len(password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect("/admin")
    try:
        name = validate_plain_text(name, "club name", re.compile(r"^[A-Za-z0-9Ā-ž'&.,() -]{2,120}$"), 120)
        salt, uhash = make_username_record(username)
        with db() as conn:
            if find_club_by_username(conn, username):
                raise sqlite3.IntegrityError
            conn.execute(
                "INSERT INTO clubs (name, username_salt, username_hash, password_hash, is_super) VALUES (?, ?, ?, ?, 0)",
                (name, salt, uhash, generate_password_hash(password)),
            )
            conn.commit()
        flash("Club created.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except sqlite3.IntegrityError:
        flash("That club name or username already exists.", "error")
    return redirect("/admin")


@app.route("/register_shooter", methods=["POST"])
@club_admin_required
def register_shooter():
    u = current_user()
    tsnz_number = request.form.get("tsnz_number", "").strip()
    first_name = request.form.get("first_name", "").strip()
    surname = request.form.get("surname", "").strip()
    dob_text = request.form.get("dob", "").strip()
    sex = request.form.get("sex", "").strip()
    grade = request.form.get("grade", "").strip()
    shooter_password = request.form.get("shooter_password", "")

    club_id = u["id"]
    if u["is_super"] and request.form.get("club_id"):
        try:
            club_id = int(request.form.get("club_id"))
        except ValueError:
            flash("Invalid club selected.", "error")
            return redirect("/admin")

    try:
        tsnz_number = validate_plain_text(tsnz_number, "TSNZ number", TSNZ_RE, 30)
        first_name = validate_plain_text(first_name, "first name", NAME_RE, 80)
        surname = validate_plain_text(surname, "surname", NAME_RE, 80)
        dob_iso = parse_dob(dob_text)
        if sex not in SEX_OPTIONS:
            raise ValueError("Select a valid sex option.")
        if grade not in GRADES:
            raise ValueError("Select a valid grade.")
        if len(shooter_password) < 8:
            raise ValueError("Shooter password must be at least 8 characters.")
        with db() as conn:
            club_exists = conn.execute("SELECT id FROM clubs WHERE id = ? AND is_super = 0", (club_id,)).fetchone()
            if not club_exists:
                raise ValueError("Invalid club selected.")
            conn.execute(
                """
                INSERT INTO shooters
                (tsnz_number, first_name, surname, dob, sex, grade, club_id, ladder_position, club_ladder_position, shooter_password_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (tsnz_number, first_name, surname, dob_iso, sex, grade, club_id, next_ladder_position(), next_club_ladder_position(club_id), generate_password_hash(shooter_password)),
            )
            conn.commit()
        reorder_by_grade()
        flash("Shooter registered.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except sqlite3.IntegrityError:
        flash("That TSNZ number is already registered.", "error")
    return redirect("/admin")


@app.route("/enter_score", methods=["POST"])
@club_admin_required
def enter_score():
    u = current_user()
    tsnz_number = request.form.get("tsnz_number", "").strip()
    score_text = request.form.get("score", "").strip()
    week = get_week_start().isoformat()

    try:
        tsnz_number = validate_plain_text(tsnz_number, "TSNZ number", TSNZ_RE, 30)
        score_points = score_to_points(score_text)
        with db() as conn:
            shooter = conn.execute("SELECT * FROM shooters WHERE tsnz_number = ? AND active = 1", (tsnz_number,)).fetchone()
            if not shooter:
                raise ValueError("No active shooter found with that TSNZ number.")
            if not u["is_super"] and shooter["club_id"] != u["id"]:
                raise ValueError("Denied: that shooter does not belong to your club.")
            existing = conn.execute("SELECT id FROM scores WHERE shooter_id = ? AND week_start = ?", (shooter["id"], week)).fetchone()
            if existing:
                raise ValueError("This shooter already has a score entered this week.")
            conn.execute(
                "INSERT INTO scores (shooter_id, club_id, week_start, score_points, entered_at) VALUES (?, ?, ?, ?, ?)",
                (shooter["id"], shooter["club_id"], week, score_points, datetime.now().isoformat(timespec="seconds")),
            )
            conn.commit()
        flash("Score entered.", "success")
    except ValueError as e:
        flash(str(e), "error")
    return redirect("/admin")


def process_week_by_start(week_start_date: date) -> tuple[bool, int, str]:
    week = week_start_date.isoformat()
    attack = get_attack_parity(week_start_date)
    with db() as conn:
        already = conn.execute("SELECT week_start FROM processed_weeks WHERE week_start = ?", (week,)).fetchone()
        if already:
            return False, 0, "This week has already been processed."

        # Weekly ladder scores are kept separate from sanctioned ranking scores.
        # They can move the optional New Zealand Ladder and the club ladders,
        # but they never create or modify rows in ranking_scores.
        id_to_score = {
            row["shooter_id"]: row
            for row in conn.execute("SELECT * FROM scores WHERE week_start = ?", (week,)).fetchall()
        }

        national_swaps = []
        if national_ladder_enabled():
            national_ladder = conn.execute(
                "SELECT * FROM shooters WHERE active = 1 ORDER BY ladder_position"
            ).fetchall()
            by_global_pos = {row["ladder_position"]: row for row in national_ladder}
            for attacker in national_ladder:
                pos = attacker["ladder_position"]
                if attack == "even":
                    if pos % 2 != 0:
                        continue
                    defender = by_global_pos.get(pos - 1)
                else:
                    if pos == 1 or pos % 2 != 1:
                        continue
                    defender = by_global_pos.get(pos - 1)
                if not defender:
                    continue
                attacker_score = id_to_score.get(attacker["id"])
                defender_score = id_to_score.get(defender["id"])
                if not attacker_score or not defender_score:
                    continue
                if attacker_score["score_points"] > defender_score["score_points"]:
                    national_swaps.append((attacker, defender, attacker_score, defender_score))

        for attacker, defender, attacker_score, defender_score in national_swaps:
            conn.execute("UPDATE shooters SET ladder_position = ? WHERE id = ?", (defender["ladder_position"], attacker["id"]))
            conn.execute("UPDATE shooters SET ladder_position = ? WHERE id = ?", (attacker["ladder_position"], defender["id"]))
            conn.execute("UPDATE scores SET result = 'won' WHERE id = ?", (attacker_score["id"],))
            conn.execute("UPDATE scores SET result = 'lost' WHERE id = ?", (defender_score["id"],))

        # Process each club ladder independently using the same weekly scores.
        club_swaps = []
        clubs = conn.execute("SELECT id FROM clubs WHERE is_super = 0").fetchall()
        for club in clubs:
            club_ladder = conn.execute(
                "SELECT * FROM shooters WHERE active = 1 AND club_id = ? ORDER BY club_ladder_position",
                (club["id"],),
            ).fetchall()
            by_club_pos = {row["club_ladder_position"]: row for row in club_ladder}
            for attacker in club_ladder:
                pos = attacker["club_ladder_position"]
                if attack == "even":
                    if pos % 2 != 0:
                        continue
                    defender = by_club_pos.get(pos - 1)
                else:
                    if pos == 1 or pos % 2 != 1:
                        continue
                    defender = by_club_pos.get(pos - 1)
                if not defender:
                    continue
                attacker_score = id_to_score.get(attacker["id"])
                defender_score = id_to_score.get(defender["id"])
                if not attacker_score or not defender_score:
                    continue
                if attacker_score["score_points"] > defender_score["score_points"]:
                    club_swaps.append((attacker, defender, attacker_score, defender_score))

        for attacker, defender, attacker_score, defender_score in club_swaps:
            conn.execute("UPDATE shooters SET club_ladder_position = ? WHERE id = ?", (defender["club_ladder_position"], attacker["id"]))
            conn.execute("UPDATE shooters SET club_ladder_position = ? WHERE id = ?", (attacker["club_ladder_position"], defender["id"]))
            conn.execute("UPDATE scores SET club_result = 'won' WHERE id = ?", (attacker_score["id"],))
            conn.execute("UPDATE scores SET club_result = 'lost' WHERE id = ?", (defender_score["id"],))

        conn.execute(
            "INSERT INTO processed_weeks (week_start, processed_at, attack_parity) VALUES (?, ?, ?)",
            (week, datetime.now().isoformat(timespec="seconds"), attack),
        )
        conn.commit()
    return True, len(club_swaps) + len(national_swaps), f"Week {display_date(week)} processed. {len(national_swaps)} New Zealand ladder swap(s) and {len(club_swaps)} club ladder swap(s) made."


def auto_process_due_weeks() -> list[str]:
    current_week_start = get_week_start()
    last_completed_week_start = current_week_start - timedelta(days=7)
    messages: list[str] = []
    with db() as conn:
        candidate_rows = conn.execute(
            """
            SELECT DISTINCT week_start
            FROM scores
            WHERE week_start <= ?
            ORDER BY week_start ASC
            """,
            (last_completed_week_start.isoformat(),),
        ).fetchall()
    for row in candidate_rows:
        week_start_date = datetime.strptime(row["week_start"], "%Y-%m-%d").date()
        processed, swaps, message = process_week_by_start(week_start_date)
        if processed:
            messages.append(message)
    return messages


def start_background_auto_processor() -> None:
    def worker():
        while True:
            try:
                auto_process_due_weeks()
            except Exception:
                pass
            time.sleep(AUTO_PROCESS_INTERVAL_SECONDS)
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()




@app.route("/enter_ranking_score", methods=["POST"])
@super_required
def enter_ranking_score():
    u = current_user()
    tsnz_number = request.form.get("tsnz_number", "").strip()
    event_name = request.form.get("event_name", "").strip()
    event_date_text = request.form.get("event_date", "").strip()
    score_text = request.form.get("score", "").strip()
    notes = request.form.get("notes", "").strip()

    try:
        tsnz_number = validate_plain_text(tsnz_number, "TSNZ number", TSNZ_RE, 30)
        event_name = validate_plain_text(event_name, "event name", re.compile(r"^[A-Za-z0-9Ā-ž'&.,()/: -]{2,160}$"), 160)
        try:
            event_date = datetime.strptime(event_date_text, "%d/%m/%Y").date().isoformat()
        except ValueError:
            raise ValueError("Event date must be in day/month/year format, e.g. 24/09/2026")
        score_points = score_to_points(score_text)
        notes = notes[:500] if notes else None
        with db() as conn:
            shooter = conn.execute("SELECT id FROM shooters WHERE tsnz_number = ? AND active = 1", (tsnz_number,)).fetchone()
            if not shooter:
                raise ValueError("No active shooter found with that TSNZ number.")
            conn.execute(
                """
                INSERT INTO ranking_scores
                (shooter_id, event_name, event_date, score_points, notes, entered_by, entered_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (shooter["id"], event_name, event_date, score_points, notes, u["id"], datetime.now().isoformat(timespec="seconds")),
            )
            conn.commit()
        flash("Sanctioned ranking score entered.", "success")
    except ValueError as e:
        flash(str(e), "error")
    return redirect("/admin")


@app.route("/update_ranking_score/<int:score_id>", methods=["POST"])
@super_required
def update_ranking_score(score_id: int):
    event_name = request.form.get("event_name", "").strip()
    event_date_text = request.form.get("event_date", "").strip()
    score_text = request.form.get("score", "").strip()
    notes = request.form.get("notes", "").strip()
    try:
        event_name = validate_plain_text(event_name, "event name", re.compile(r"^[A-Za-z0-9Ā-ž'&.,()/: -]{2,160}$"), 160)
        try:
            event_date = datetime.strptime(event_date_text, "%d/%m/%Y").date().isoformat()
        except ValueError:
            raise ValueError("Event date must be in day/month/year format, e.g. 24/09/2026")
        score_points = score_to_points(score_text)
        notes = notes[:500] if notes else None
        with db() as conn:
            conn.execute(
                "UPDATE ranking_scores SET event_name = ?, event_date = ?, score_points = ?, notes = ? WHERE id = ?",
                (event_name, event_date, score_points, notes, score_id),
            )
            conn.commit()
        flash("Sanctioned ranking score updated.", "success")
    except ValueError as e:
        flash(str(e), "error")
    return redirect("/admin")


@app.route("/delete_ranking_score/<int:score_id>", methods=["POST"])
@super_required
def delete_ranking_score(score_id: int):
    with db() as conn:
        conn.execute("DELETE FROM ranking_scores WHERE id = ?", (score_id,))
        conn.commit()
    flash("Sanctioned ranking score deleted.", "success")
    return redirect("/admin")


@app.route("/toggle_national_ladder", methods=["POST"])
@super_required
def toggle_national_ladder():
    enabled = request.form.get("national_ladder_enabled", "0") == "1"
    set_app_setting("national_ladder_enabled", "1" if enabled else "0")
    flash("New Zealand Ladder turned on." if enabled else "New Zealand Ladder turned off.", "success")
    return redirect("/admin")


@app.route("/set_attack_parity", methods=["POST"])
@super_required
def set_attack_parity():
    parity = request.form.get("attack_parity", "").strip().lower()
    if parity not in {"odd", "even"}:
        flash("Select a valid attack setting.", "error")
        return redirect("/admin")

    week_start = get_week_start().isoformat()
    u = current_user()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO week_settings (week_start, attack_parity, updated_at, updated_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(week_start) DO UPDATE SET
                attack_parity = excluded.attack_parity,
                updated_at = excluded.updated_at,
                updated_by = excluded.updated_by
            """,
            (week_start, parity, datetime.now().isoformat(timespec="seconds"), u["id"]),
        )
        conn.commit()
    attack_text, defend_text = describe_attack_parity(parity)
    flash(f"This week updated: {attack_text}; {defend_text}.", "success")
    return redirect("/admin")


@app.route("/process_week", methods=["POST"])
@super_required
def process_week():
    week_start_date = get_week_start() - timedelta(days=7)
    processed, swaps, message = process_week_by_start(week_start_date)
    flash(message, "success" if processed else "error")
    return redirect("/admin")



@app.route("/move_global_shooter/<int:shooter_id>/<direction>", methods=["POST"])
@super_required
def move_global_shooter(shooter_id: int, direction: str):
    if direction not in {"up", "down"}:
        flash("Invalid move direction.", "error")
        return redirect("/admin")
    moved = swap_global_position(shooter_id, direction)
    flash("Global ladder position updated." if moved else "That shooter cannot be moved further.", "success" if moved else "error")
    return redirect("/admin")


@app.route("/move_club_shooter/<int:shooter_id>/<direction>", methods=["POST"])
@club_admin_required
def move_club_shooter(shooter_id: int, direction: str):
    if direction not in {"up", "down"}:
        flash("Invalid move direction.", "error")
        return redirect("/admin")
    u = current_user()
    allowed_club_id = None if u["is_super"] else u["id"]
    moved = swap_club_position(shooter_id, direction, allowed_club_id)
    flash("Club ladder position updated." if moved else "That shooter cannot be moved further, or is not in your club.", "success" if moved else "error")
    return redirect("/admin")


@app.route("/delete_shooter/<int:shooter_id>", methods=["POST"])
@super_required
def delete_shooter(shooter_id: int):
    with db() as conn:
        shooter = conn.execute("SELECT club_id FROM shooters WHERE id = ?", (shooter_id,)).fetchone()
        conn.execute("UPDATE shooters SET active = 0 WHERE id = ?", (shooter_id,))
        normalize_global_positions(conn)
        if shooter:
            normalize_club_positions(conn, shooter["club_id"])
        conn.commit()
    flash("Shooter removed from active ladder.", "success")
    return redirect("/admin")


@app.route("/delete_score/<int:score_id>", methods=["POST"])
@super_required
def delete_score(score_id: int):
    with db() as conn:
        conn.execute("DELETE FROM scores WHERE id = ?", (score_id,))
        conn.commit()
    flash("Score deleted.", "success")
    return redirect("/admin")


if __name__ == "__main__":
    init_db()
    start_background_auto_processor()
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=5000, type=int)
    args = parser.parse_args()
    app.run(host=args.host, port=args.port, debug=True, use_reloader=False)
