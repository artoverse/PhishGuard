from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()

class ScanSession(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # NEW: Isolate scans by user
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    domain = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="completed")
    registered_count = db.Column(db.Integer, default=0)
    total_permutations = db.Column(db.Integer, default=0)  # for progress bar

class DetectedDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('scan_session.id'))
    domain = db.Column(db.String(255), nullable=False)
    risk_score = db.Column(db.Float)
    risk_status = db.Column(db.String(20))
    enriched_data = db.Column(db.JSON)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('scan_session.id'))  # NEW: per-session alerts
    domain = db.Column(db.String(255))
    message = db.Column(db.String(500))
    severity = db.Column(db.String(20))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_approved = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    # Email alert preferences
    alert_email = db.Column(db.String(255), nullable=True)          # recipient address (None = disabled)
    alert_malicious_only = db.Column(db.Boolean, default=False)     # True = only Malicious (not Suspicious)
    alert_on_find = db.Column(db.Boolean, default=True)             # True = instant email when threat found during scan
    alert_on_complete = db.Column(db.Boolean, default=True)         # True = digest email when scan finishes

class ScheduledScan(db.Model):
    """Persists a recurring monitoring schedule for a domain."""
    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain       = db.Column(db.String(255), nullable=False)
    interval_hrs = db.Column(db.Integer, default=24)   # 1 | 6 | 24 | 168
    enabled      = db.Column(db.Boolean, default=True)
    last_run_at  = db.Column(db.DateTime, nullable=True)
    next_run_at  = db.Column(db.DateTime, nullable=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)