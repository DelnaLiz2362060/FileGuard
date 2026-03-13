import hashlib, os, json, time, threading, queue, secrets, re, smtplib
from datetime import datetime
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import (Flask, jsonify, render_template, request,
                   Response, stream_with_context, session, redirect, url_for)
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import database as db

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__)
# Persist secret key so sessions survive restarts
_KEY_FILE = ".secret_key"
if os.environ.get("SECRET_KEY"):
    app.secret_key = os.environ["SECRET_KEY"]
elif os.path.exists(_KEY_FILE):
    app.secret_key = open(_KEY_FILE).read().strip()
else:
    _key = secrets.token_hex(32)
    open(_KEY_FILE, "w").write(_key)
    app.secret_key = _key

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True

def smtp_config():
    """Read SMTP settings fresh from environment every time they are needed.
    Single source of truth — removes the duplicate / inconsistent reads that
    were scattered across _send_email_worker, test_email, and smtp_status."""
    return {
        "host": os.environ.get("SMTP_HOST", "smtp.gmail.com"),
        "port": int(os.environ.get("SMTP_PORT", "0")),   # 0 = auto-detect
        "user": os.environ.get("SMTP_USER", "joannadelna@gmail.com").strip(),
        "pass": os.environ.get("SMTP_PASSWORD", "tdgq yrqs afaq erei").strip(),
    }

# ── ML Model ──────────────────────────────────────────────────────────────────
rng = np.random.default_rng(42)

def _normal(n=500):
    return np.column_stack([
        rng.integers(8,18,n), rng.uniform(0.1,2.0,n), rng.integers(0,2,n),
        rng.uniform(0.1,0.5,n), rng.uniform(60,3600,n), rng.integers(1,5,n),
        np.zeros(n), np.zeros(n)])

def _anomaly(n=50):
    return np.column_stack([
        rng.integers(0,6,n), rng.uniform(50,500,n), rng.integers(0,2,n),
        rng.uniform(5,20,n), rng.uniform(0.1,5,n), rng.integers(10,50,n),
        np.ones(n), np.ones(n)])

_train        = np.vstack([_normal(), _anomaly()])
scaler        = StandardScaler()
_train_scaled = scaler.fit_transform(_train)
model         = IsolationForest(n_estimators=200, contamination=0.09,
                                max_samples="auto", random_state=42, n_jobs=-1)
model.fit(_train_scaled)
_raw_train              = model.score_samples(_train_scaled)
_SCORE_MIN, _SCORE_MAX  = float(_raw_train.min()), float(_raw_train.max())

def ml_score(features):
    arr    = np.array(features, dtype=float).reshape(1, -1)
    scaled = scaler.transform(arr)
    raw    = float(model.score_samples(scaled)[0])
    normed = float(np.clip((raw - _SCORE_MAX) / (_SCORE_MIN - _SCORE_MAX), 0, 1))
    label  = "ANOMALY" if normed > 0.5 else ("SUSPICIOUS" if normed > 0.30 else "NORMAL")
    return round(normed, 3), label

# ── Per-user in-memory state ──────────────────────────────────────────────────
# All dicts are keyed by user_id (int) so each user has completely isolated state.

user_watched   = {}   # uid -> { path -> {hash, size, added_at, status, is_dir, children} }
user_events    = {}   # uid -> [ {time, level, message} ]
user_changes   = {}   # uid -> { path -> [timestamps] }

# SSE clients keyed by user_id so pushes are user-scoped
sse_clients    = {}   # uid -> [Queue, ...]
sse_lock       = threading.Lock()

def _ensure_user(uid):
    """Initialise per-user buckets if they don't exist yet."""
    if uid not in user_watched:  user_watched[uid]  = {}
    if uid not in user_events:   user_events[uid]   = []
    if uid not in user_changes:  user_changes[uid]  = {}
    if uid not in sse_clients:   sse_clients[uid]   = []

# ── Helpers ───────────────────────────────────────────────────────────────────
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def now_str():
    return datetime.now().strftime("%H:%M:%S")

def file_size_str(path):
    try: b = os.path.getsize(path)
    except OSError: return "N/A"
    for u in ["B", "KB", "MB", "GB"]:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} TB"

def push_sse(uid, data):
    """Push SSE payload only to queues belonging to this user."""
    payload = json.dumps(data)
    with sse_lock:
        for q in sse_clients.get(uid, []):
            q.put(payload)

def add_event(uid, level, message, path=None, score=None, label=None):
    entry = {"time": now_str(), "level": level, "message": message}
    user_events.setdefault(uid, []).append(entry)
    push_sse(uid, {"type": "log", "entry": entry})
    try: db.event_add(level, message, path, score, label)
    except Exception: pass

def _build_html(body):
    return f"""<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:#0f172a;font-family:Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:32px 0">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0"
       style="background:#1e293b;border-radius:12px;overflow:hidden;border-left:4px solid #ef4444">
<tr><td style="padding:24px">
  <h2 style="margin:0 0 16px;color:#ef4444;font-size:20px">&#128274; FileGuard Security Alert</h2>
  <div style="background:#0f172a;border-radius:8px;padding:16px;margin-bottom:16px">
    <pre style="margin:0;color:#94a3b8;font-size:13px;white-space:pre-wrap;font-family:monospace">{body}</pre>
  </div>
  <p style="margin:0;color:#475569;font-size:11px">FileGuard &middot; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</td></tr></table></td></tr></table>
</body></html>"""

def _send_email_worker(to, subject, body):
    """Send email — tries STARTTLS (587) then SSL (465). Uses smtp_config() as single source of truth."""
    cfg       = smtp_config()
    smtp_host = cfg["host"]
    smtp_port = cfg["port"]
    smtp_user = cfg["user"]
    smtp_pass = cfg["pass"]

    print(f"\n[EMAIL] ─────────────────────────────────")
    print(f"[EMAIL] To:      {to}")
    print(f"[EMAIL] Subject: {subject}")
    print(f"[EMAIL] Host:    {smtp_host}")
    print(f"[EMAIL] User:    {smtp_user if smtp_user else '(NOT SET)'}")
    print(f"[EMAIL] Pass:    {'(SET, len=%d)' % len(smtp_pass) if smtp_pass else '(NOT SET)'}")

    if not smtp_user or not smtp_pass:
        print("[EMAIL] ✗ SKIPPED — SMTP_USER and SMTP_PASSWORD must be set as environment variables.")
        print("[EMAIL]   Run:  export SMTP_USER=you@gmail.com")
        print("[EMAIL]         export SMTP_PASSWORD=your_app_password")
        print("[EMAIL] ─────────────────────────────────\n")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"FileGuard <{smtp_user}>"
    msg["To"]      = to
    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(_build_html(body), "html"))

    raw = msg.as_string()
    last_error = None

    # Bug 7 fixed: port 25 removed — blocked by virtually all ISPs and cloud hosts.
    # Auto-detect only tries 587 (STARTTLS) and 465 (SSL).
    if smtp_port != 0:
        attempts = [(smtp_port, smtp_port == 465)]
    else:
        attempts = [(587, False), (465, True)]

    for port, use_ssl in attempts:
        try:
            print(f"[EMAIL] Trying {'SSL' if use_ssl else 'STARTTLS'} on port {port}…")
            if use_ssl:
                with smtplib.SMTP_SSL(smtp_host, port, timeout=15) as s:
                    s.ehlo()
                    s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, to, raw)
            else:
                with smtplib.SMTP(smtp_host, port, timeout=15) as s:
                    s.ehlo()
                    s.starttls()
                    s.ehlo()
                    s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, to, raw)
            print(f"[EMAIL] ✓ Sent successfully → {to} (port {port})")
            print("[EMAIL] ─────────────────────────────────\n")
            return  # success — stop trying
        except smtplib.SMTPAuthenticationError as e:
            print(f"[EMAIL] ✗ Auth failed on port {port}: {e}")
            print("[EMAIL]   Gmail users: use an App Password, not your regular password.")
            print("[EMAIL]   Get one at: https://myaccount.google.com/apppasswords")
            last_error = e
            break  # auth failure won't be fixed by trying another port
        except Exception as e:
            print(f"[EMAIL] ✗ Failed on port {port}: {e}")
            last_error = e

    print(f"[EMAIL] ✗ All attempts failed. Last error: {last_error}")
    print("[EMAIL] ─────────────────────────────────\n")

def send_email(to, subject, body):
    """Fire-and-forget background send.
    Bug 4 fixed: daemon=False so the thread is not silently killed when the
    server restarts mid-send. A 15-second SMTP timeout means it finishes
    quickly regardless — it won't block a clean shutdown."""
    threading.Thread(target=_send_email_worker, args=(to, subject, body), daemon=False).start()

def alert_user(uid, subject, body):
    """Send email alert to a specific user if their alerts are enabled."""
    u = db.user_get_by_id(uid)
    if not u:
        print(f"[ALERT] No user found for uid={uid}")
        return
    # Bug 5 fixed: use explicit int(1) check instead of truthiness.
    # alert_enabled can be None (missing column in old DB row) or the string "0"
    # which would both be falsy but have different meanings. int() normalises safely.
    if int(u.get("alert_enabled") or 0) != 1:
        print(f"[ALERT] Alerts disabled for {u['email']}, skipping.")
        return
    print(f"[ALERT] Sending alert to {u['email']}: {subject}")
    send_email(u["email"], subject, body)

def get_all_files(path):
    if os.path.isfile(path): yield path
    elif os.path.isdir(path):
        for root, _, files in os.walk(path):
            for f in files: yield os.path.join(root, f)

def _file_list(uid):
    out = []
    for p, info in user_watched.get(uid, {}).items():
        child_count = len(info.get("children", {})) if info.get("is_dir") else None
        out.append({
            "path": p, "fname": os.path.basename(p),
            "hash": (info["hash"][:16] + "…") if info.get("hash") else "N/A",
            "size": info.get("size", "N/A"), "status": info.get("status", "INTACT"),
            "added_at": info.get("added_at", ""), "is_dir": info.get("is_dir", False),
            "child_count": child_count,
        })
    return out

# ── Watcher thread ────────────────────────────────────────────────────────────
def _handle_change(uid, root_path, changed_file, new_hash):
    fname  = os.path.basename(changed_file)
    now_ts = time.time()

    ts_list = user_changes.setdefault(uid, {}).setdefault(changed_file, [])
    ts_list.append(now_ts)
    ts_list[:] = [t for t in ts_list if now_ts - t < 600]
    burst   = len(ts_list)
    last_iv = (now_ts - ts_list[-2]) if len(ts_list) >= 2 else 3600
    hour    = datetime.now().hour
    weekend = int(datetime.now().weekday() >= 5)
    after_h = int(hour < 8 or hour >= 20)
    rapid   = int(last_iv < 10)

    try: size_delta = os.path.getsize(changed_file) / 1024
    except OSError: size_delta = 0

    features = [hour, min(size_delta, 500), weekend, min(burst / 10, 20),
                min(last_iv, 3600), min(burst, 50), after_h, rapid]
    score, label = ml_score(features)

    add_event(uid, "WARN",     f"[CHANGE] {changed_file}", path=changed_file)
    add_event(uid, "CRITICAL", f"Hash mismatch! Now: {new_hash[:12]}…", path=changed_file)
    add_event(uid, "ML",       f"Score: {score} → {label}",
              path=changed_file, score=score, label=label)

    level = "critical" if score > 0.75 else ("warn" if score > 0.50 else "info")
    push_sse(uid, {"type": "alert", "level": level, "path": changed_file, "fname": fname,
                   "message": f"'{fname}' modified! ML: {label} (score {score})",
                   "score": score, "label": label, "status": "MODIFIED"})

    # Always email on any change — use emoji/subject to indicate severity
    icon    = "🚨" if score > 0.75 else ("⚠️" if score > 0.50 else "🔔")
    subject = f"{icon} FileGuard: {label} detected in {fname}"
    body    = (f"File modified: {changed_file}\n"
               f"ML Label: {label}\n"
               f"Anomaly Score: {score}\n"
               f"Changes in last 10 min: {burst}\n"
               f"Interval since last change: {last_iv:.1f}s\n"
               f"After hours: {bool(after_h)}\n"
               f"Time: {datetime.now()}")
    alert_user(uid, subject, body)

    wf = db.wf_get_by_path(root_path)
    if wf:
        db.wf_update(root_path, new_hash, "MODIFIED", file_size_str(changed_file))
        db.alog_add(wf["id"], "MODIFIED", score, label, burst, bool(after_h))

def watcher_loop():
    while True:
        time.sleep(2)
        # Iterate over every user's watched paths
        for u_id, paths in list(user_watched.items()):
            for root_path, info in list(paths.items()):
                is_dir = info.get("is_dir", False)

                if is_dir:
                    if not os.path.exists(root_path):
                        if info.get("status") != "DELETED":
                            user_watched[u_id][root_path]["status"] = "DELETED"
                            add_event(u_id, "CRITICAL", f"Folder DELETED: {root_path}", path=root_path)
                            push_sse(u_id, {"type": "alert", "level": "critical",
                                          "path": root_path, "fname": os.path.basename(root_path),
                                          "message": f"Folder DELETED: {root_path}", "status": "DELETED"})
                            alert_user(u_id, "🚨 FileGuard: Watched Folder DELETED",
                                       f"CRITICAL: Watched folder has been deleted!\n\n"
                                       f"Folder: {root_path}\n"
                                       f"Time: {datetime.now()}\n\n"
                                       f"Immediate investigation recommended.")
                        continue

                    current_children = set(get_all_files(root_path))
                    known_children   = set(info.get("children", {}).keys())

                    for nf in current_children - known_children:
                        try: h = sha256_file(nf)
                        except Exception: continue
                        user_watched[u_id][root_path]["children"][nf] = h
                        add_event(u_id, "INFO", f"New file in folder: {nf}", path=nf)
                        push_sse(u_id, {"type": "alert", "level": "info", "path": nf,
                                      "fname": os.path.basename(nf),
                                      "message": f"New file: {nf}", "status": "NEW"})

                    for df in known_children - current_children:
                        del user_watched[u_id][root_path]["children"][df]
                        add_event(u_id, "CRITICAL", f"File deleted from folder: {df}", path=df)
                        push_sse(u_id, {"type": "alert", "level": "critical", "path": df,
                                      "fname": os.path.basename(df),
                                      "message": f"DELETED: {df}", "status": "DELETED"})
                        alert_user(u_id, "🚨 FileGuard: File DELETED from watched folder",
                                   f"CRITICAL: File deleted from watched folder!\n\n"
                                   f"File: {df}\n"
                                   f"Watched folder: {root_path}\n"
                                   f"Time: {datetime.now()}\n\n"
                                   f"Immediate investigation recommended.")

                    for fp, old_h in list(info.get("children", {}).items()):
                        if not os.path.exists(fp): continue
                        try: new_h = sha256_file(fp)
                        except Exception: continue
                        if new_h != old_h:
                            _handle_change(u_id, root_path, fp, new_h)
                            user_watched[u_id][root_path]["children"][fp] = new_h

                    push_sse(u_id, {"type": "files", "files": _file_list(u_id)})

                else:
                    if not os.path.exists(root_path):
                        if info.get("status") != "DELETED":
                            user_watched[u_id][root_path]["status"] = "DELETED"
                            fname = os.path.basename(root_path)
                            add_event(u_id, "CRITICAL", f"File DELETED: {root_path}", path=root_path)
                            push_sse(u_id, {"type": "alert", "level": "critical",
                                          "path": root_path, "fname": fname,
                                          "message": f"'{fname}' DELETED!", "status": "DELETED"})
                            alert_user(u_id, "🚨 FileGuard: Watched File DELETED",
                                       f"CRITICAL: A monitored file has been deleted!\n\n"
                                       f"File: {root_path}\n"
                                       f"Time: {datetime.now()}\n\n"
                                       f"Immediate investigation recommended.")
                        continue

                    try: current_hash = sha256_file(root_path)
                    except Exception: continue

                    if current_hash != info["hash"]:
                        _handle_change(u_id, root_path, root_path, current_hash)
                        user_watched[u_id][root_path]["hash"]   = current_hash
                        user_watched[u_id][root_path]["status"] = "MODIFIED"
                        user_watched[u_id][root_path]["size"]   = file_size_str(root_path)
                        push_sse(u_id, {"type": "files", "files": _file_list(u_id)})

threading.Thread(target=watcher_loop, daemon=True).start()

# ── Auth decorator ────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Unauthorized"}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

def uid():
    """Shorthand: current user's id from session."""
    return session["user_id"]

# ── Auth routes ───────────────────────────────────────────────────────────────
@app.route("/login")
def login_page():
    if "user_id" in session: return redirect(url_for("index"))
    return render_template("login.html")

@app.route("/register")
def register_page():
    if "user_id" in session: return redirect(url_for("index"))
    return render_template("register.html")

@app.route("/api/auth/register", methods=["POST"])
def register():
    data  = request.json or {}
    email = (data.get("email") or "").strip().lower()
    pwd   = data.get("password") or ""
    name  = (data.get("name") or "").strip()
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"ok": False, "error": "Invalid email."}), 400
    if len(pwd) < 8:
        return jsonify({"ok": False, "error": "Password must be ≥ 8 characters."}), 400
    if db.user_get_by_email(email):
        return jsonify({"ok": False, "error": "Email already registered."}), 409
    db.user_create(email, name or email.split("@")[0], pwd)
    # Bug 6 fixed: only attempt welcome email when SMTP is actually configured.
    # Previously this spawned a thread on every registration guaranteed to do nothing,
    # with no feedback to the user that the email was skipped.
    cfg = smtp_config()
    if cfg["user"] and cfg["pass"]:
        send_email(email, "Welcome to FileGuard",
                   f"Hi {name or email},\n\nYour account is ready.\nYou will receive security alerts here.")
    return jsonify({"ok": True})

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    u = db.user_check_password(
        (data.get("email") or "").strip().lower(), data.get("password") or "")
    if not u:
        return jsonify({"ok": False, "error": "Invalid email or password."}), 401
    session["user_id"] = u["id"]
    _ensure_user(u["id"])   # initialise per-user buckets on login
    return jsonify({"ok": True, "name": u["name"]})

@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/auth/me")
@login_required
def me():
    u = db.user_get_by_id(uid())
    return jsonify({"email": u["email"], "name": u["name"],
                    "alert_enabled": bool(u["alert_enabled"])})

@app.route("/api/auth/toggle-alerts", methods=["POST"])
@login_required
def toggle_alerts():
    enabled = db.user_toggle_alerts(uid())
    return jsonify({"ok": True, "alert_enabled": enabled})

# ── Main routes ───────────────────────────────────────────────────────────────
@app.route("/")
@login_required
def index():
    _ensure_user(uid())
    u = db.user_get_by_id(uid())
    return render_template("index.html", user_id=uid(), user_email=u["email"], user_name=u["name"])

@app.route("/api/events")
@login_required
def sse_stream():
    current_uid = uid()
    _ensure_user(current_uid)
    q = queue.Queue()
    with sse_lock:
        sse_clients[current_uid].append(q)

    def stream():
        try:
            # Send only THIS user's files and events on connect
            init = {"type": "init",
                    "files": _file_list(current_uid),
                    "log":   user_events.get(current_uid, [])[-20:]}
            yield f"data: {json.dumps(init)}\n\n"
            while True:
                try:
                    payload = q.get(timeout=25)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            with sse_lock:
                lst = sse_clients.get(current_uid, [])
                if q in lst: lst.remove(q)

    return Response(stream_with_context(stream()), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

@app.route("/api/add-file", methods=["POST"])
@login_required
def add_file():
    current_uid = uid()
    _ensure_user(current_uid)
    path = (request.json or {}).get("path", "").strip()
    if not path:
        return jsonify({"ok": False, "error": "No path provided."}), 400
    if not os.path.exists(path):
        return jsonify({"ok": False, "error": f"Path not found: {path}"}), 404
    if path in user_watched[current_uid]:
        return jsonify({"ok": False, "error": "Already monitoring this path."}), 409

    is_dir = os.path.isdir(path)
    if is_dir:
        children = {}
        for fp in get_all_files(path):
            try: children[fp] = sha256_file(fp)
            except Exception: pass
        user_watched[current_uid][path] = {
            "hash": None, "size": f"{len(children)} files",
            "added_at": now_str(), "status": "INTACT",
            "is_dir": True, "children": children,
        }
        add_event(current_uid, "INFO",
                  f"Folder added: {path} ({len(children)} files)", path=path)
        add_event(current_uid, "SUCCESS",
                  f"Folder '{os.path.basename(path)}' is now watched.")
        db.wf_add(path, True, "", f"{len(children)} files", current_uid)
    else:
        h = sha256_file(path)
        user_watched[current_uid][path] = {
            "hash": h, "size": file_size_str(path),
            "added_at": now_str(), "status": "INTACT", "is_dir": False,
        }
        add_event(current_uid, "INFO",    f"File added: {path}", path=path)
        add_event(current_uid, "INFO",    f"Baseline SHA-256: {h[:16]}…")
        add_event(current_uid, "SUCCESS", f"'{os.path.basename(path)}' is now watched.")
        db.wf_add(path, False, h, file_size_str(path), current_uid)

    push_sse(current_uid, {"type": "files", "files": _file_list(current_uid)})
    return jsonify({"ok": True})

@app.route("/api/remove-file", methods=["POST"])
@login_required
def remove_file():
    current_uid = uid()
    path = (request.json or {}).get("path", "").strip()
    if path not in user_watched.get(current_uid, {}):
        return jsonify({"ok": False, "error": "Not monitored."}), 404
    del user_watched[current_uid][path]
    add_event(current_uid, "INFO", f"Stopped monitoring: {path}")
    db.wf_remove(path)
    push_sse(current_uid, {"type": "files", "files": _file_list(current_uid)})
    return jsonify({"ok": True})

@app.route("/api/logs")
@login_required
def get_logs():
    return jsonify({"log": db.event_list(100)})

@app.route("/api/access-logs")
@login_required
def access_logs():
    rows = db.alog_list_by_user(uid(), 100)
    return jsonify({"logs": [{
        "time":        r["timestamp"],
        "path":        r["path"],
        "fname":       os.path.basename(r["path"]),
        "event":       r["event_type"],
        "score":       r["ml_score"],
        "label":       r["ml_label"],
        "burst":       r["burst_count"],
        "after_hours": bool(r["after_hours"]),
    } for r in rows]})

@app.route("/api/db-files")
@login_required
def db_files():
    files = db.wf_list_by_user(uid())
    return jsonify({"files": [{
        "path":          f["path"],
        "fname":         os.path.basename(f["path"]),
        "status":        f["status"],
        "is_dir":        bool(f["is_dir"]),
        "hash":          (f["current_hash"][:16] + "…") if f.get("current_hash") else "N/A",
        "size":          f["file_size"] or "N/A",
        "added_at":      f["added_at"] or "—",
        "last_modified": f["last_modified"] or "—",
    } for f in files]})

@app.route("/api/status")
@login_required
def status():
    return jsonify({"files": _file_list(uid())})

@app.route("/api/reset", methods=["POST"])
@login_required
def reset():
    current_uid = uid()
    user_watched.get(current_uid, {}).clear()
    user_events.get(current_uid, []).clear()
    user_changes.get(current_uid, {}).clear()
    db.wf_clear_by_user(current_uid)
    db.event_clear()
    db.alog_clear()
    push_sse(current_uid, {"type": "files", "files": []})
    return jsonify({"ok": True})


@app.route("/api/smtp-status")
@login_required
def smtp_status():
    """Return current SMTP configuration so the UI can show what's set."""
    cfg = smtp_config()   # Bug 1 fixed: use single smtp_config() helper
    u = db.user_get_by_id(uid())
    return jsonify({
        "smtp_host":      cfg["host"],
        "smtp_port":      cfg["port"] if cfg["port"] != 0 else "auto",
        "smtp_user_set":  bool(cfg["user"]),
        "smtp_pass_set":  bool(cfg["pass"]),
        "smtp_user":      cfg["user"] if cfg["user"] else "(not set)",
        "alert_enabled":  int(u.get("alert_enabled") or 0) == 1,
        "recipient":      u["email"],
        "ready":          bool(cfg["user"] and cfg["pass"]),
    })

@app.route("/api/test-email", methods=["POST"])
@login_required
def test_email():
    """Send a synchronous test email and return the exact result to the UI."""
    # Bug 3 fixed: removed unused 'import ssl as _ssl'
    # Bug 1 & 2 fixed: use smtp_config() instead of duplicated os.environ reads
    cfg = smtp_config()
    smtp_host = cfg["host"]
    smtp_port = cfg["port"]
    smtp_user = cfg["user"]
    smtp_pass = cfg["pass"]
    u = db.user_get_by_id(uid())

    if not smtp_user or not smtp_pass:
        return jsonify({
            "ok": False,
            "error": "SMTP_USER and SMTP_PASSWORD are not set. "
                     "Set them as environment variables before starting the server:\n"
                     "  export SMTP_USER=you@gmail.com\n"
                     "  export SMTP_PASSWORD=your_16char_app_password"
        }), 400

    body = (f"Test alert from FileGuard.\n\n"
            f"If you received this, email alerts are working!\n\n"
            f"Account: {u['email']}\nTime: {datetime.now()}")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "✅ FileGuard — Email Test"
    msg["From"]    = f"FileGuard <{smtp_user}>"
    msg["To"]      = u["email"]
    msg.attach(MIMEText(body, "plain"))
    msg.attach(MIMEText(_build_html(body), "html"))
    raw = msg.as_string()

    # Bug 7 fixed: port 25 removed — blocked by virtually all cloud hosts and ISPs
    attempts = [(smtp_port, smtp_port == 465)] if smtp_port != 0 else [(587, False), (465, True)]
    last_error = None

    for port, use_ssl in attempts:
        try:
            if use_ssl:
                with smtplib.SMTP_SSL(smtp_host, port, timeout=15) as s:
                    s.ehlo(); s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, u["email"], raw)
            else:
                with smtplib.SMTP(smtp_host, port, timeout=15) as s:
                    s.ehlo(); s.starttls(); s.ehlo()
                    s.login(smtp_user, smtp_pass)
                    s.sendmail(smtp_user, u["email"], raw)
            return jsonify({"ok": True,
                            "message": f"✓ Email sent to {u['email']} via port {port}. Check your inbox (and spam)."})
        except smtplib.SMTPAuthenticationError:
            return jsonify({
                "ok": False,
                "error": f"Authentication failed for {smtp_user}.\n\n"
                         "Gmail users must use an App Password (not your regular password).\n"
                         "Generate one at: https://myaccount.google.com/apppasswords\n"
                         "(Requires 2-Step Verification to be enabled on your Google account)"
            }), 401
        except Exception as e:
            last_error = str(e)

    return jsonify({"ok": False,
                    "error": f"Could not connect to {smtp_host}.\n"
                             f"Last error: {last_error}\n\n"
                             "Check SMTP_HOST is correct and your network allows outbound SMTP."}), 500

if __name__ == "__main__":
    db.init_db()
    print("🔒  FileGuard → http://localhost:5000")
    app.run(debug=False, port=5000, threaded=True)
