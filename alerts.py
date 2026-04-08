from flask import current_app
import smtplib
from email.mime.text import MIMEText

def send_alert(domain, risk_status, score):
    msg = f"ALERT: {domain} is {risk_status} (score: {score})\nAction required."
    # Console + DB log
    print(f"[NSA-ALERT] {msg}")
    # Email placeholder
    try:
        # smtplib.sendmail(...) → add your SMTP in .env
        pass
    except: pass