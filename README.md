# SFICA — Smart File Integrity Checking Application

Multi-user file integrity monitoring system with ML-based anomaly detection.

## Features

- 🔐 **Multi-user auth** — Email/password + Google OAuth
- 📁 **Real file watching** — Monitors actual files on disk with SHA-256 hashing
- 🤖 **ML anomaly detection** — IsolationForest model scores every file change
- 🔔 **Dual notifications** — In-app bell + email alerts (SMTP)
- 📊 **Model analytics** — Confusion matrix, accuracy, precision, recall, F1 score
- 🏷️ **Human-in-the-loop** — Label alerts to measure & improve model performance

## Quick Start

```bash
# Install dependencies
pip install flask scikit-learn numpy

# Configure (copy .env.example to .env and fill in SMTP details)
cp .env.example .env

# Run
python app.py
# → http://localhost:5000
```

## New Feature: Model Analytics & Confusion Matrix

### What it does

The **Analytics** page (`/analytics`) shows:
- **Confusion Matrix** — Visual 2x2 grid showing:
  - **TP (True Positive)**: ML correctly flagged a real threat
  - **FP (False Positive)**: ML raised a false alarm
  - **TN (True Negative)**: ML correctly ignored safe changes
  - **FN (False Negative)**: ML missed a real threat
- **Accuracy** — Overall correctness rate
- **Precision** — How many flagged threats were real?
- **Recall** — How many real threats did we catch?
- **F1 Score** — Harmonic mean of precision & recall

### How to use it

1. **Trigger alerts** — Add files, edit them, and let the ML model generate alerts
2. **Label alerts** — On the Analytics page, mark each alert as:
   - ✓ **Real Threat** — The file change was actually malicious/unauthorized
   - ✕ **False Alarm** — The change was legitimate (you made it, or it's safe)
3. **Watch metrics update** — As you label more alerts, the confusion matrix and accuracy scores update in real time

### Why this matters

- **Validate the ML model** — See how well the IsolationForest performs on *your* data
- **Identify weaknesses** — High FP rate? Model is too sensitive. High FN rate? It's missing threats.
- **Continuous improvement** — Labeled data could be used to retrain the model (future feature)

### Example interpretation

```
Confusion Matrix after 20 labeled alerts:
  TP: 15   FP: 2
  FN: 1    TN: 2

Accuracy:  85%   (17 correct out of 20)
Precision: 88%   (15 real threats / 17 flagged)
Recall:    94%   (15 caught / 16 real threats)
F1 Score:  91%
```

This means:
- Model caught 15/16 real threats (good recall!)
- Only 2 false alarms out of 17 flags (good precision!)
- 1 real threat slipped through (room for improvement)

## File Structure

```
sfica2/
├── app.py              ← Flask routes + auth
├── models.py           ← SQLite DB + metrics calculation
├── watcher.py          ← Background file monitor
├── notifications.py    ← Email + SSE push
├── requirements.txt
├── .env.example
└── templates/
    ├── base.html       ← Nav + notification system
    ├── login.html
    ├── register.html
    ├── dashboard.html  ← Main monitoring UI
    └── analytics.html  ← NEW: Confusion matrix & metrics
```

## Database Schema

### New field in `alerts` table:
- `ground_truth` — NULL (unlabeled), 'TRUE_POSITIVE', or 'FALSE_POSITIVE'

This enables tracking which alerts were real threats vs false alarms.

## API Endpoints (New)

- `POST /api/alert/label` — Mark an alert as TRUE_POSITIVE or FALSE_POSITIVE
- `GET /api/metrics` — Get confusion matrix + accuracy/precision/recall/F1

## Configuration

Set these in `.env`:

```bash
# Required for email alerts
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Optional for Google OAuth
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...
```

## Tech Stack

- **Backend**: Flask, SQLite, scikit-learn (IsolationForest)
- **Frontend**: Vanilla JS, SSE (Server-Sent Events)
- **No extra dependencies** — runs with just Flask + sklearn + numpy

---

Built with ❤️ for cybersecurity monitoring
