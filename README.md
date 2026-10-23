# 🔐 PhishGuard — Phishing URL Detection System

> **Minor Project** | Python · Flask · URL Analysis

A full-stack web application that analyzes URLs for phishing indicators using
heuristic pattern matching, feature extraction, and a weighted risk-scoring engine.

---

## 📸 Features

| Feature | Details |
|---|---|
| **20+ URL Features** | Length, IP check, entropy, keywords, subdomains, TLD, etc. |
| **Risk Scoring** | Weighted 0–100 score normalized from all features |
| **3-Level Classification** | ✅ Safe · ⚠️ Suspicious · 🚨 Phishing |
| **Real-time Analysis** | Flask REST API with animated scanning UI |
| **Scan History** | Stores last 50 scans in memory |
| **Statistics Dashboard** | Live counters for total / phishing / suspicious / safe |
| **Premium Dark UI** | Cybersecurity themed, fully responsive |

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python app.py
```

### 3. Open in Browser

```
http://127.0.0.1:5000
```

---

## 🧠 Detection Logic

The system extracts the following features from every URL:

| # | Feature | Weight |
|---|---|---|
| 1 | URL Length > 75 chars | +1 to +3 |
| 2 | Missing HTTPS | +2 |
| 3 | IP Address as Domain | +5 |
| 4 | URL Shortener Service | +4 |
| 5 | @ Symbol in URL | +5 |
| 6 | Double Slash Redirect | +3 |
| 7 | Hyphens in Domain | +2 to +4 |
| 8 | Subdomain Depth ≥ 3 | +2 to +6 |
| 9 | Suspicious TLD (.tk, .ml...) | +4 |
| 10 | Brand Keywords in Domain | +3 to +9 |
| 11 | Phishing Keywords in Path | +2 to +8 |
| 12 | Digits in Domain ≥ 3 | +2 to +4 |
| 13 | Special Characters > 4 | +1 to +4 |
| 14 | Non-standard Port | +3 |
| 15 | Domain Entropy > 3.5 | +1 to +3 |
| 16 | Long Query String > 100 | +2 |
| 17 | Many Query Parameters > 5 | +2 |
| 18 | Long Domain Name > 20 | +1 to +2 |
| 19 | Hex Encoded Characters > 3 | +1 to +2 |
| 20 | Embedded URL (Redirect) | +5 |

**Final Score** = `min(sum_of_weights / 80 * 100, 100)`

| Score Range | Verdict |
|---|---|
| 0 – 19 | ✅ Safe |
| 20 – 44 | ⚠️ Suspicious |
| 45 – 100 | 🚨 Phishing |

---

## 📁 Project Structure

```
Minor/
├── app.py                  # Flask application & REST API
├── requirements.txt        # Python dependencies
├── detector/
│   ├── __init__.py
│   ├── url_analyzer.py     # Analysis pipeline & risk scoring
│   └── feature_extractor.py # 20+ feature extraction functions
├── templates/
│   └── index.html          # Jinja2 HTML template
├── static/
│   ├── css/style.css       # Premium dark-mode UI
│   ├── js/main.js          # Frontend JS (API calls, rendering)
│   └── img/logo.png        # Project logo
└── README.md
```

---

## 🔌 API Reference

### `POST /api/analyze`

Analyze a URL for phishing indicators.

**Request Body:**
```json
{ "url": "https://example.com" }
```

**Response:**
```json
{
  "url": "...",
  "score": 72,
  "risk": {
    "verdict": "PHISHING",
    "label": "Phishing Detected",
    "color": "#ff1744",
    "message": "...",
    "recommendation": "..."
  },
  "features": { ... },
  "red_flags": [ ... ],
  "suspicious_count": 8
}
```

### `GET /api/history`
Returns last 20 scan results.

### `GET /api/stats`
Returns total/phishing/suspicious/safe counts.

---

## 🛠️ Tech Stack

- **Backend:** Python 3.x, Flask 3.x
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Analysis:** Custom heuristic rule engine
- **Fonts:** Inter, JetBrains Mono, Orbitron (Google Fonts)

---

## ⚠️ Disclaimer

This project is built for **educational purposes** as a college minor project.
It uses heuristic rules — not a substitute for enterprise security tools.
Always verify suspicious URLs with trusted security platforms like VirusTotal.

---

*PhishGuard — Minor Project | Developed with Python & Flask*
