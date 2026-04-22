"""
scheduler.py — Continuous Background Monitoring Engine
======================================================
Uses APScheduler's BackgroundScheduler with a single polling job that
fires every 60 seconds.  For each enabled ScheduledScan whose next_run_at
is in the past the engine:
  1. Creates a new ScanSession
  2. Triggers _do_scan() via a daemon thread (same path as manual scans)
  3. Registers a one-shot completion callback that compares results with
     the previous scan and emails the user about net-new threats only.
  4. Advances next_run_at by interval_hrs hours.
"""

import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

# Populated by init_scheduler(); avoids circular imports.
_app         = None
_db          = None
_do_scan_fn  = None   # reference to app._do_scan
_active_scans = None  # reference to app.active_scans
_ScanSession  = None
_DetectedDomain = None
_ScheduledScan  = None
_User           = None
_ScanState      = None

_scheduler = BackgroundScheduler(timezone="UTC")


def init_scheduler(app, db, do_scan_fn, active_scans_dict,
                   ScanSession, DetectedDomain, ScheduledScan, User, ScanState):
    """Call once from app.py after db.create_all()."""
    global _app, _db, _do_scan_fn, _active_scans
    global _ScanSession, _DetectedDomain, _ScheduledScan, _User, _ScanState

    _app            = app
    _db             = db
    _do_scan_fn     = do_scan_fn
    _active_scans   = active_scans_dict
    _ScanSession    = ScanSession
    _DetectedDomain = DetectedDomain
    _ScheduledScan  = ScheduledScan
    _User           = User
    _ScanState      = ScanState

    _scheduler.add_job(
        _poll_due_jobs,
        trigger='interval',
        seconds=60,
        id='phishguard_monitor_poll',
        replace_existing=True,
    )
    _scheduler.start()
    logger.info("[scheduler] Background monitoring engine started.")


def shutdown_scheduler():
    if _scheduler.running:
        _scheduler.shutdown(wait=False)


# ── Core polling loop ─────────────────────────────────────────────────────────

def _poll_due_jobs():
    """Runs every 60 s.  Checks for overdue schedules and fires them."""
    now = datetime.utcnow()
    with _app.app_context():
        due = _ScheduledScan.query.filter(
            _ScheduledScan.enabled == True,             # noqa: E712
            _ScheduledScan.next_run_at <= now
        ).all()

        for sched in due:
            try:
                _fire_scan(sched)
            except Exception as exc:
                logger.error("[scheduler] Error firing scan for %s: %s", sched.domain, exc)


def _fire_scan(sched):
    """Create a ScanSession and launch _do_scan in a daemon thread."""
    from dnstwist import DomainFuzz  # local import to avoid startup cost
    import dnstwist

    domain = sched.domain
    logger.info("[scheduler] Triggering scheduled scan for %s (id=%s)", domain, sched.id)

    # ── Generate permutations (same logic as manual scan) ─────────────────
    try:
        fuzzer = dnstwist.DomainFuzz(domain)
        fuzzer.generate()
        all_domains = [
            r['domain'] for r in fuzzer.domains
            if r.get('domain') and r['domain'] != domain
        ]
    except Exception as exc:
        logger.error("[scheduler] DomainFuzz failed for %s: %s", domain, exc)
        return

    if not all_domains:
        logger.warning("[scheduler] No permutations for %s, skipping.", domain)
        _advance_schedule(sched)
        return

    # ── Record previous scan's threats for diff later ─────────────────────
    prev_malicious = set(
        d.domain for d in _DetectedDomain.query.join(_ScanSession)
        .filter(
            _ScanSession.domain == domain,
            _ScanSession.user_id == sched.user_id,
            _DetectedDomain.risk_status == 'Malicious'
        ).all()
    )

    # ── Create new ScanSession ─────────────────────────────────────────────
    session_id = str(uuid.uuid4())
    session = _ScanSession(
        id=session_id,
        user_id=sched.user_id,
        domain=domain,
        status='running',
        total_permutations=len(all_domains),
    )
    _db.session.add(session)
    _db.session.commit()

    state = _ScanState(domain)
    state.all_domains = all_domains
    _active_scans[session_id] = state

    # ── Listen for scan completion to send diff alert ─────────────────────
    user = _User.query.get(sched.user_id)

    def _on_complete():
        """Called after the scan thread finishes."""
        try:
            with _app.app_context():
                new_threats = [
                    d for d in _DetectedDomain.query.filter_by(session_id=session_id).all()
                    if d.risk_status == 'Malicious' and d.domain not in prev_malicious
                ]

                if new_threats and user and user.alert_email:
                    _send_schedule_alert(user, domain, new_threats, session_id)

                _advance_schedule(sched.id)
        except Exception as exc:
            logger.error("[scheduler] Completion callback error: %s", exc)

    # ── Launch scan thread ─────────────────────────────────────────────────
    def _scan_with_callback():
        _do_scan_fn(session_id, domain)
        _on_complete()

    threading.Thread(target=_scan_with_callback, daemon=True).start()
    logger.info("[scheduler] Scan thread launched for %s (session=%s)", domain, session_id)


def _advance_schedule(sched_or_id):
    """Set last_run_at = now, next_run_at = now + interval_hrs."""
    with _app.app_context():
        sched_id = sched_or_id if isinstance(sched_or_id, int) else sched_or_id.id
        sched = _ScheduledScan.query.get(sched_id)
        if sched:
            now = datetime.utcnow()
            sched.last_run_at = now
            sched.next_run_at = now + timedelta(hours=sched.interval_hrs)
            _db.session.commit()
            logger.info("[scheduler] Next run for %s scheduled at %s",
                        sched.domain, sched.next_run_at)


# ── Alert on new threats ──────────────────────────────────────────────────────

def _send_schedule_alert(user, brand_domain, new_threats, session_id):
    """Sends email listing net-new malicious domains since the last scheduled scan."""
    import os
    from mailer import send_threat_alert

    smtp_cfg = {
        'server':     os.environ.get('MAIL_SERVER', ''),
        'port':       int(os.environ.get('MAIL_PORT', 587)),
        'username':   os.environ.get('MAIL_USERNAME', ''),
        'password':   os.environ.get('MAIL_PASSWORD', ''),
        'from_email': os.environ.get('MAIL_FROM', ''),
        'use_tls':    os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
    }

    threats_payload = [
        {
            'domain':      d.domain,
            'risk_status': d.risk_status,
            'risk_score':  d.risk_score,
        }
        for d in new_threats
    ]

    try:
        send_threat_alert(
            to_email=user.alert_email,
            session_domain=brand_domain,
            threats=threats_payload,
            smtp_config=smtp_cfg,
        )
        logger.info("[scheduler] New-threat alert sent for %s → %s", brand_domain, user.alert_email)
    except Exception as exc:
        logger.error("[scheduler] Alert email failed: %s", exc)
