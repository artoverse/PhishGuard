# PhishGuard

A phishing domain detection tool we built as part of our final year project. It scans for lookalike domains that could be impersonating a target brand and scores them based on how likely they are to be malicious.

## What it does

When you give it a domain like `apple.com`, it:
1. Generates hundreds of lookalike domain names (typos, character swaps, added words etc.)
2. Checks which ones are actually registered via DNS
3. Enriches each one with WHOIS data, VirusTotal results, SSL info and web content
4. Scores each domain out of 100 based on how suspicious it looks
5. Shows everything in a live dashboard

We also added some extra features along the way like scheduled monitoring, PDF reports and automated email alerts to brand security teams when phishing domains are found.

## How the scoring works

We use a combination of rule-based scoring and an XGBoost ML model trained on real phishing datasets. The rule engine looks at things like:
- How recently the domain was registered
- Whether VirusTotal flags it
- Visual similarity to the original domain
- Suspicious page content (login forms, credential harvesting etc.)
- SSL certificate status

The ML model acts as a secondary layer. We put in "score floors" so that if the rules are very confident something is malicious, the ML can't drag the score back down.

## Tech stack

- Python + Flask (backend)
- Flask-SocketIO for real-time updates
- SQLite with WAL mode (handles concurrent writes from scan threads)
- dnstwist for domain permutations  
- XGBoost + scikit-learn for the ML part
- APScheduler for background scheduled scans
- Tailwind CSS + vanilla JS (frontend)

## Setup

**Requirements: Python 3.9+**

```bash
git clone https://github.com/yourusername/phishguard.git
cd phishguard

python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env with your SMTP credentials and VirusTotal API key

python app.py
```

Open `http://127.0.0.1:8000` — default login is `admin` / `admin`.

### Environment variables

Copy `.env.example` to `.env` and fill in:

| Variable | What it's for |
|---|---|
| `SECRET_KEY` | Flask session key (any random string) |
| `VIRUSTOTAL_API_KEY` | Free at virustotal.com — needed for VT enrichment |
| `MAIL_*` | Gmail App Password for alert emails |

VirusTotal is optional but the scores will be less accurate without it.

## Features

- **Live scanning** — results appear in real-time via WebSockets as DNS resolves
- **Pause / Resume** — scans can be paused and resumed from a checkpoint
- **Scheduled monitoring** — set a domain to auto-rescan daily/weekly, only get alerted on *new* threats
- **Brand notifications** — one-click email to the real brand's security team (does WHOIS lookup to find their abuse contact)
- **Export** — CSV, JSON, PDF per session
- **User accounts** — admin approval required, each user sees only their own scans

## Project structure

```
phishguard/
├── app.py              # Flask routes + API endpoints
├── enricher.py         # WHOIS, VT, SSL, web content enrichment
├── risk_analyzer.py    # Deterministic scoring engine
├── ml_scorer.py        # XGBoost model wrapper
├── scheduler.py        # APScheduler background monitoring
├── mailer.py           # Email templates + SMTP dispatch
├── models.py           # SQLAlchemy models
├── reporters.py        # PDF / CSV / JSON export
├── config.py           # App config from .env
├── static/             # JS + CSS
└── templates/          # HTML templates
```

## Notes

- The `phishguard_xgb.pkl` model file in the repo was trained by us using `train_xgb.py` on the PhiUSIIL Phishing URL dataset. You don't need to retrain it to run the app.
- The `phishing_raw.csv` training data is not included (15MB) — see `train_xgb.py` if you want to retrain.
- On first run the app creates the SQLite database automatically and sets up a default admin user.

## License

MIT
