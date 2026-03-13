"""
database.py - SQLite3 persistence (no ORM needed)
"""
import sqlite3, os
from werkzeug.security import generate_password_hash, check_password_hash
from contextlib import contextmanager

DB_PATH = os.environ.get("DB_PATH", "file_integrity.db")

@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn; conn.commit()
    except Exception:
        conn.rollback(); raise
    finally:
        conn.close()

def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            alert_enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS watched_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            path TEXT UNIQUE NOT NULL,
            is_dir INTEGER DEFAULT 0,
            current_hash TEXT,
            file_size TEXT,
            status TEXT DEFAULT 'INTACT',
            added_at TEXT DEFAULT (datetime('now')),
            last_modified TEXT,
            added_by INTEGER REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS file_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT DEFAULT (datetime('now')),
            level TEXT, message TEXT, file_path TEXT,
            ml_score REAL, ml_label TEXT
        );
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER NOT NULL REFERENCES watched_files(id) ON DELETE CASCADE,
            timestamp TEXT DEFAULT (datetime('now')),
            event_type TEXT, ml_score REAL, ml_label TEXT,
            burst_count INTEGER DEFAULT 1, after_hours INTEGER DEFAULT 0
        );
        """)

    # Migration: add ground_truth column for ML evaluation
    with get_conn() as c:
        try:
            c.execute("ALTER TABLE file_events ADD COLUMN ground_truth TEXT")
        except Exception:
            pass
    # Migration: ensure alert_enabled column exists and all users have it set
    with get_conn() as c:
        # Add column if missing (old databases)
        try:
            c.execute("ALTER TABLE users ADD COLUMN alert_enabled INTEGER DEFAULT 1")
        except Exception:
            pass  # column already exists
        # Fix any users who somehow got alert_enabled=0 or NULL — set to 1 by default
        c.execute("UPDATE users SET alert_enabled=1 WHERE alert_enabled IS NULL OR alert_enabled=0")
    print(f"[DB] Ready: {DB_PATH}")

# Users
def user_create(email, name, password):
    ph = generate_password_hash(password)
    with get_conn() as c:
        cur = c.execute("INSERT INTO users (email,name,password_hash,alert_enabled) VALUES (?,?,?,1)", (email,name,ph))
        return cur.lastrowid

def user_get_by_email(email):
    with get_conn() as c:
        r = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        return dict(r) if r else None

def user_get_by_id(uid):
    with get_conn() as c:
        r = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        return dict(r) if r else None

def user_check_password(email, password):
    u = user_get_by_email(email)
    if u and check_password_hash(u["password_hash"], password):
        return u
    return None

def user_toggle_alerts(uid):
    with get_conn() as c:
        c.execute("UPDATE users SET alert_enabled=1-alert_enabled WHERE id=?", (uid,))
    return bool(user_get_by_id(uid)["alert_enabled"])

def users_with_alerts():
    with get_conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM users WHERE alert_enabled=1").fetchall()]

# WatchedFiles
def wf_add(path, is_dir, current_hash, file_size, added_by):
    with get_conn() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO watched_files (path,is_dir,current_hash,file_size,status,added_by) VALUES (?,?,?,?,'INTACT',?)",
            (path, int(is_dir), current_hash, file_size, added_by))
        return cur.lastrowid

def wf_remove(path):
    with get_conn() as c:
        c.execute("DELETE FROM watched_files WHERE path=?", (path,))

def wf_get_by_path(path):
    with get_conn() as c:
        r = c.execute("SELECT * FROM watched_files WHERE path=?", (path,)).fetchone()
        return dict(r) if r else None

def wf_update(path, current_hash, status, file_size=None):
    with get_conn() as c:
        if file_size:
            c.execute("UPDATE watched_files SET current_hash=?,status=?,last_modified=datetime('now'),file_size=? WHERE path=?",
                      (current_hash, status, file_size, path))
        else:
            c.execute("UPDATE watched_files SET current_hash=?,status=?,last_modified=datetime('now') WHERE path=?",
                      (current_hash, status, path))

def wf_list_all():
    with get_conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM watched_files ORDER BY added_at DESC").fetchall()]

def wf_clear():
    with get_conn() as c:
        c.execute("DELETE FROM watched_files")

# Events
def event_add(level, message, file_path=None, ml_score=None, ml_label=None):
    with get_conn() as c:
        c.execute("INSERT INTO file_events (level,message,file_path,ml_score,ml_label) VALUES (?,?,?,?,?)",
                  (level, message, file_path, ml_score, ml_label))

def event_list(limit=100):
    with get_conn() as c:
        rows = c.execute("SELECT * FROM file_events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in reversed(rows)]

def event_clear():
    with get_conn() as c:
        c.execute("DELETE FROM file_events")

# Access logs
def alog_add(file_id, event_type, ml_score=None, ml_label=None, burst_count=1, after_hours=False):
    with get_conn() as c:
        c.execute("INSERT INTO access_logs (file_id,event_type,ml_score,ml_label,burst_count,after_hours) VALUES (?,?,?,?,?,?)",
                  (file_id, event_type, ml_score, ml_label, burst_count, int(after_hours)))

def alog_list(limit=100):
    with get_conn() as c:
        rows = c.execute("""
            SELECT al.*, wf.path FROM access_logs al
            JOIN watched_files wf ON al.file_id=wf.id
            ORDER BY al.timestamp DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]

def alog_clear():
    with get_conn() as c:
        c.execute("DELETE FROM access_logs")

# User-scoped queries
def wf_list_by_user(uid):
    with get_conn() as c:
        return [dict(r) for r in c.execute(
            "SELECT * FROM watched_files WHERE added_by=? ORDER BY added_at DESC", (uid,)).fetchall()]

def wf_clear_by_user(uid):
    with get_conn() as c:
        c.execute("DELETE FROM watched_files WHERE added_by=?", (uid,))

def alog_list_by_user(uid, limit=100):
    with get_conn() as c:
        rows = c.execute("""
            SELECT al.*, wf.path FROM access_logs al
            JOIN watched_files wf ON al.file_id=wf.id
            WHERE wf.added_by=?
            ORDER BY al.timestamp DESC LIMIT ?""", (uid, limit)).fetchall()
        return [dict(r) for r in rows]
