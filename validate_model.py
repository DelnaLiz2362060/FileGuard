import sqlite3
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, confusion_matrix

# ── Connect to FileGuard's real database ─────────────────────────────────────
import os
DB_PATH = os.environ.get("DB_PATH", "file_integrity.db")

def load_real_events():
    """
    Pull every access-log row that has an ML prediction attached.
    Ground truth  : event_type == 'MODIFIED'  → 1 (real threat)
                    anything else              → 0 (normal)
    Model output  : ml_score > 0.5            → 1 (model said threat)
                    ml_score <= 0.5            → 0 (model said normal)
    Only rows that have a non-NULL ml_score are included so we only
    evaluate events the model actually scored.
    """
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute("""
        SELECT event_type, ml_score, ml_label
        FROM   access_logs
        WHERE  ml_score IS NOT NULL
    """)
    rows = cur.fetchall()
    con.close()
    return rows


def generate_fileguard_accuracy():
    rows = load_real_events()

    if not rows:
        print("-" * 45)
        print("FILEGUARD PERFORMANCE VALIDATION REPORT")
        print("-" * 45)
        print("No scored events found in the database.")
        print("Watch some files and trigger modifications")
        print("on your website first, then re-run this script.")
        print("-" * 45)
        return

    # Ground truth: was this event actually a file modification / threat?
    y_true = np.array([1 if r["event_type"] == "MODIFIED" else 0 for r in rows])

    # Model prediction: did the ML score cross the 0.5 anomaly threshold?
    # (mirrors the logic in app.py: label == 'ANOMALY' when score > 0.5)
    y_pred = np.array([1 if (r["ml_score"] or 0) > 0.5 else 0 for r in rows])

    total      = len(rows)
    n_threats  = int(y_true.sum())
    n_normal   = total - n_threats

    # Guard: precision_score needs at least one positive prediction
    if y_pred.sum() == 0:
        precision = 0.0
    else:
        precision = precision_score(y_true, y_pred, zero_division=0) * 100

    accuracy = accuracy_score(y_true, y_pred) * 100
    cm       = confusion_matrix(y_true, y_pred, labels=[0, 1])

    tn = int(cm[0][0])
    fp = int(cm[0][1])
    fn = int(cm[1][0])
    tp = int(cm[1][1])

    print("-" * 45)
    print("FILEGUARD PERFORMANCE VALIDATION REPORT")
    print("  (based on REAL events from fileguard.db)")
    print("-" * 45)
    print(f"Total events evaluated:  {total}")
    print(f"  ↳ Real threats (MODIFIED):  {n_threats}")
    print(f"  ↳ Normal events:            {n_normal}")
    print("-" * 45)
    print(f"Overall Accuracy:  {accuracy:.1f}%")
    print(f"Model Precision:   {precision:.1f}%")
    print("-" * 45)
    print(f"True Positives  (Attacks Caught):    {tp}")
    print(f"True Negatives  (Normal Files Safe): {tn}")
    print(f"False Positives (False Alarms):      {fp}")
    print(f"False Negatives (Missed Threats):    {fn}")
    print("-" * 45)

    if total < 20:
        print(f"⚠  Only {total} scored events — results may not be")
        print("   representative yet. Trigger more file changes.")
        print("-" * 45)


if __name__ == "__main__":
    generate_fileguard_accuracy()