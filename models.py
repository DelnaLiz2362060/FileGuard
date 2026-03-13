"""
models.py — Database layer for FileGuard
Pure sqlite3, no ORM dependency.
Tables: users, watched_files, file_events, access_logs

Matches the schema and functions used by app.py / database.py exactly.
"""

import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import contextmanager

DB_PATH = os.environ.get("DB_PATH", "file_integrity.db")


# ── Connection ─────────────────────────────────────────────────────────────────

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ─────────────────────────────────────────────────────────────────────

def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            email           TEXT    UNIQUE NOT NULL,
            name            TEXT    NOT NULL,
            password_hash   TEXT    NOT NULL,
            alert_enabled   INTEGER DEFAULT 1,
            created_at      TEXT    DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS watched_files (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            path            TEXT    UNIQUE NOT NULL,
            is_dir          INTEGER DEFAULT 0,
            current_hash    TEXT,
            file_size       TEXT,
            status          TEXT    DEFAULT 'INTACT',   -- INTACT | MODIFIED | DELETED
            added_at        TEXT    DEFAULT (datetime('now')),
            last_modified   TEXT,
            added_by        INTEGER REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS file_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    DEFAULT (datetime('now')),
            level           TEXT,
            message         TEXT,
            file_path       TEXT,
            ml_score        REAL,
            ml_label        TEXT,
            ground_truth    TEXT    -- NULL | TRUE_POSITIVE | FALSE_POSITIVE
        );

        CREATE TABLE IF NOT EXISTS access_logs (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id         INTEGER NOT NULL REFERENCES watched_files(id) ON DELETE CASCADE,
            timestamp       TEXT    DEFAULT (datetime('now')),
            event_type      TEXT,
            ml_score        REAL,
            ml_label        TEXT,
            burst_count     INTEGER DEFAULT 1,
            after_hours     INTEGER DEFAULT 0
        );
        """)

    # ── Safe migrations (idempotent) ───────────────────────────────────────────
    _run_migration("ALTER TABLE file_events ADD COLUMN ground_truth TEXT")
    _run_migration("ALTER TABLE users ADD COLUMN alert_enabled INTEGER DEFAULT 1")

    print(f"[DB] Ready: {DB_PATH}")


def _run_migration(sql):
    """Run a migration statement, silently skip if it has already been applied."""
    with get_conn() as conn:
        try:
            conn.execute(sql)
        except Exception:
            pass  # Column already exists — safe to ignore


# ── Users ──────────────────────────────────────────────────────────────────────

def user_create(email, name, password):
    """Create a new user and return their new id."""
    ph = generate_password_hash(password)
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (email, name, password_hash, alert_enabled) VALUES (?, ?, ?, 1)",
            (email, name, ph),
        )
        return cur.lastrowid


def user_get_by_email(email):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return dict(row) if row else None


def user_get_by_id(uid):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        return dict(row) if row else None


def user_check_password(email, password):
    """Return user dict if credentials are valid, else None."""
    u = user_get_by_email(email)
    if u and check_password_hash(u["password_hash"], password):
        return u
    return None


def user_toggle_alerts(uid):
    """Flip alert_enabled for a user. Returns the new boolean state."""
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET alert_enabled = 1 - alert_enabled WHERE id = ?", (uid,)
        )
    return bool(user_get_by_id(uid)["alert_enabled"])


def users_with_alerts():
    """Return all users who have alerts enabled."""
    with get_conn() as conn:
        return [
            dict(r)
            for r in conn.execute("SELECT * FROM users WHERE alert_enabled = 1").fetchall()
        ]


# ── Watched Files ──────────────────────────────────────────────────────────────

def wf_add(path, is_dir, current_hash, file_size, added_by):
    """
    Insert a new watched path. Returns the new row id, or the existing row id
    if the path is already present (avoids the INSERT OR IGNORE lastrowid=0 bug).
    """
    existing = wf_get_by_path(path)
    if existing:
        return existing["id"]
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO watched_files
               (path, is_dir, current_hash, file_size, status, added_by)
               VALUES (?, ?, ?, ?, 'INTACT', ?)""",
            (path, int(is_dir), current_hash, file_size, added_by),
        )
        return cur.lastrowid


def wf_remove(path):
    with get_conn() as conn:
        conn.execute("DELETE FROM watched_files WHERE path = ?", (path,))


def wf_get_by_path(path):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM watched_files WHERE path = ?", (path,)).fetchone()
        return dict(row) if row else None


def wf_update(path, current_hash, status, file_size=None):
    with get_conn() as conn:
        if file_size:
            conn.execute(
                """UPDATE watched_files
                   SET current_hash = ?, status = ?, last_modified = datetime('now'), file_size = ?
                   WHERE path = ?""",
                (current_hash, status, file_size, path),
            )
        else:
            conn.execute(
                """UPDATE watched_files
                   SET current_hash = ?, status = ?, last_modified = datetime('now')
                   WHERE path = ?""",
                (current_hash, status, path),
            )


def wf_list_all():
    with get_conn() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM watched_files ORDER BY added_at DESC"
            ).fetchall()
        ]


def wf_list_by_user(uid):
    with get_conn() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT * FROM watched_files WHERE added_by = ? ORDER BY added_at DESC",
                (uid,),
            ).fetchall()
        ]


def wf_clear():
    """Remove ALL watched files (admin use only)."""
    with get_conn() as conn:
        conn.execute("DELETE FROM watched_files")


def wf_clear_by_user(uid):
    """Remove only the watched files belonging to a specific user."""
    with get_conn() as conn:
        conn.execute("DELETE FROM watched_files WHERE added_by = ?", (uid,))


# ── File Events ────────────────────────────────────────────────────────────────

def event_add(level, message, file_path=None, ml_score=None, ml_label=None):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO file_events (level, message, file_path, ml_score, ml_label) VALUES (?, ?, ?, ?, ?)",
            (level, message, file_path, ml_score, ml_label),
        )


def event_list(limit=100):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM file_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


def event_clear():
    with get_conn() as conn:
        conn.execute("DELETE FROM file_events")


# ── Access Logs ────────────────────────────────────────────────────────────────

def alog_add(file_id, event_type, ml_score=None, ml_label=None, burst_count=1, after_hours=False):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO access_logs
               (file_id, event_type, ml_score, ml_label, burst_count, after_hours)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (file_id, event_type, ml_score, ml_label, burst_count, int(after_hours)),
        )


def alog_list(limit=100):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT al.*, wf.path
               FROM access_logs al
               JOIN watched_files wf ON al.file_id = wf.id
               ORDER BY al.timestamp DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def alog_list_by_user(uid, limit=100):
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT al.*, wf.path
               FROM access_logs al
               JOIN watched_files wf ON al.file_id = wf.id
               WHERE wf.added_by = ?
               ORDER BY al.timestamp DESC LIMIT ?""",
            (uid, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def alog_clear():
    with get_conn() as conn:
        conn.execute("DELETE FROM access_logs")


# ── ML Metrics ─────────────────────────────────────────────────────────────────
# ml_label values produced by app.py ml_score():
#   "ANOMALY"    → normed > 0.50
#   "SUSPICIOUS" → normed > 0.30
#   "BENIGN"     → everything else   ← matches ground_truth logic below

def get_model_metrics_for_user(uid):
    """
    Calculate confusion-matrix metrics from file_events that have been
    labeled by the user (ground_truth IS NOT NULL) and belong to files
    watched by this user.
    """
    with get_conn() as conn:
        rows = conn.execute(
            """SELECT fe.ml_label, fe.ground_truth
               FROM file_events fe
               JOIN watched_files wf ON fe.file_path = wf.path
               WHERE wf.added_by = ?
                 AND fe.ground_truth IS NOT NULL""",
            (uid,),
        ).fetchall()

    if not rows:
        return None

    # ML "threat" = ANOMALY or SUSPICIOUS; "safe" = BENIGN
    # User labels: TRUE_POSITIVE = real threat, FALSE_POSITIVE = false alarm
    tp = sum(1 for r in rows if r["ml_label"] in ("ANOMALY", "SUSPICIOUS") and r["ground_truth"] == "TRUE_POSITIVE")
    fp = sum(1 for r in rows if r["ml_label"] in ("ANOMALY", "SUSPICIOUS") and r["ground_truth"] == "FALSE_POSITIVE")
    tn = sum(1 for r in rows if r["ml_label"] == "BENIGN"                  and r["ground_truth"] == "FALSE_POSITIVE")
    fn = sum(1 for r in rows if r["ml_label"] == "BENIGN"                  and r["ground_truth"] == "TRUE_POSITIVE")

    total     = len(rows)
    accuracy  = (tp + tn) / total          if total            else 0.0
    precision = tp / (tp + fp)             if (tp + fp)        else 0.0
    recall    = tp / (tp + fn)             if (tp + fn)        else 0.0
    f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy":         round(accuracy,  3),
        "precision":        round(precision, 3),
        "recall":           round(recall,    3),
        "f1_score":         round(f1,        3),
        "total_labeled":    total,
    }


def label_event(event_id, ground_truth):
    """
    Mark a file_event row as TRUE_POSITIVE or FALSE_POSITIVE.
    ground_truth must be one of: 'TRUE_POSITIVE', 'FALSE_POSITIVE', None
    """
    assert ground_truth in ("TRUE_POSITIVE", "FALSE_POSITIVE", None)
    with get_conn() as conn:
        conn.execute(
            "UPDATE file_events SET ground_truth = ? WHERE id = ?",
            (ground_truth, event_id),
        )
