from flask import Flask, request, jsonify, render_template, Response, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlite3
from config import Config
import dnstwist
import threading
import queue as queue_module
import uuid
import os
import csv
import io
import json
import traceback
import time
from datetime import datetime

from enricher import enrich_domain
from risk_analyzer import analyze_risk, get_sld
from Levenshtein import distance as lev_distance
from models import db, ScanSession, DetectedDomain, Alert

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config.from_object(Config)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Use NullPool for SQLite: every db call gets a fresh connection that is
# immediately closed after use — no pool threads fighting over the same connection.
from sqlalchemy.pool import NullPool
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    **app.config.get('SQLALCHEMY_ENGINE_OPTIONS', {}),
    'poolclass': NullPool,
}

db.init_app(app)

socketio = SocketIO(app, async_mode='threading', cors_allowed_origins='*', logger=False, engineio_logger=False)

os.makedirs(os.path.join(os.path.dirname(__file__), 'instance'), exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    from models import User
    return db.session.get(User, int(user_id))

# Enable WAL journal mode on every new SQLite connection.
# WAL allows concurrent readers + one writer, eliminating most "database is locked" errors.
@event.listens_for(Engine, 'connect')
def set_sqlite_wal(dbapi_conn, connection_record):
    if isinstance(dbapi_conn, sqlite3.Connection):
        dbapi_conn.execute('PRAGMA journal_mode=WAL')
        dbapi_conn.execute('PRAGMA busy_timeout=10000')   # 10 000 ms

with app.app_context():
    db.create_all()
    
    # Safely inject new columns into SQLite if they're missing
    try:
        db.session.execute(db.text("ALTER TABLE user ADD COLUMN is_approved BOOLEAN DEFAULT 0"))
        db.session.commit()
    except Exception:
        db.session.rollback()
        
    try:
        db.session.execute(db.text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
        db.session.commit()
    except Exception:
        db.session.rollback()
        
    try:
        db.session.execute(db.text("ALTER TABLE user ADD COLUMN last_seen DATETIME"))
        db.session.commit()
    except Exception:
        db.session.rollback()
        
    # NEW: Migrate ScanSession to support user isolation
    try:
        db.session.execute(db.text("ALTER TABLE scan_session ADD COLUMN user_id INTEGER REFERENCES user(id)"))
        db.session.commit()
    except Exception:
        db.session.rollback()
    
    # Auto-create default admin user if no users exist
    from models import User
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        default_admin = User(
            username='admin',
            password_hash=generate_password_hash('admin'),
            is_approved=True,
            is_admin=True
        )
        db.session.add(default_admin)
        db.session.commit()
        print('✅ Generated default admin user (username: admin, password: admin)')
    else:
        # Upgrade existing admin user if necessary
        if not admin.is_admin or not admin.is_approved:
            admin.is_admin = True
            admin.is_approved = True
            db.session.commit()
            print('✅ Upgraded existing admin user with full permissions')

    # On restart, any session still marked 'running' has no live thread —
    # mark them 'paused' so users can resume or delete them cleanly.
    try:
        orphans = ScanSession.query.filter_by(status='running').all()
        for s in orphans:
            s.status = 'paused'
        if orphans:
            db.session.commit()
            print(f'⚠️  Marked {len(orphans)} orphaned running sessions as paused on startup')
    except Exception as _e:
        db.session.rollback()

# ─── Per-session Scan State ───────────────────────────────────────────────────

class ScanState:
    """Holds mutable runtime state for one active scan session."""
    def __init__(self, domain):
        self.domain = domain
        self.stop_event = threading.Event()   # set → signal thread to pause
        self.phase = 'dns'                    # 'dns' | 'enrichment' | 'done'
        self.all_domains = []                 # all Permutation objects (fuzzer.domains)
        self.pending_dns = []                 # Permutations NOT yet DNS-resolved
        self.pending_enrich = []              # Permutations resolved, not yet enriched
        self.scanners = []                    # active dnstwist.Scanner threads
        self.work_queue = None
        self.dns_total   = 0                  # total DNS permutations to resolve
        self.dns_done    = 0                  # how many have been resolved so far
        self.enrich_total = 0                 # total domains to enrich

active_scans: dict[str, ScanState] = {}      # session_id → ScanState

# ─── Core Scan Worker ─────────────────────────────────────────────────────────

def emit_scan_log(session_id: str, message: str, level: str = 'info'):
    """Emit a live execution log to the frontend Session Logs tab."""
    if socketio:
        socketio.emit('scan_log', {
            'session_id': session_id,
            'message': message,
            'level': level,
            'timestamp': datetime.utcnow().isoformat()
        })

def _do_scan(session_id: str, domain: str,
             pending_dns=None, pending_enrich=None):
    """
    Worker thread: runs DNS resolution + enrichment for one session.
    Can be called fresh (pending_dns=None, pending_enrich=None) or
    as a resume (with saved pending_dns / pending_enrich lists).
    Results are stored ONLY under session_id so domains NEVER mix.
    """
    state = active_scans.get(session_id)
    if not state:
        return

    with app.app_context():
        enriched_count = 0
        # Count already enriched results (from before a resume)
        try:
            enriched_count = DetectedDomain.query.filter_by(session_id=session_id).count()
        except Exception:
            pass

        try:
            # ── Phase 1: DNS Resolution ───────────────────────────────────────
            if pending_enrich is None:
                # Decide what to resolve: either a partial list (resume) or all
                to_resolve = pending_dns if pending_dns is not None else state.all_domains
                state.phase = 'dns'
                
                if pending_dns is not None:
                    emit_scan_log(session_id, f"Resuming Phase 1: DNS Resolution ({len(to_resolve)} permutations remaining)...", 'info')
                else:
                    emit_scan_log(session_id, f"Phase 1: DNS Resolution started. {len(to_resolve)} total permutations to check.", 'info')

                work_queue = queue_module.Queue()
                for p in to_resolve:
                    work_queue.put(p)
                state.work_queue = work_queue

                # DNS resolution is pure I/O — more threads = faster completion.
                # dnstwist itself defaults to cpu_count+4; we scale with domain count
                # so small scans stay lean while large ones (600 perms) finish fast.
                n_threads = min(200, max(1, len(to_resolve)))
                emit_scan_log(session_id, f"Booting {n_threads} concurrent DNS resolver threads for {len(to_resolve)} permutations.", 'info')

                scanners = [dnstwist.Scanner(work_queue) for _ in range(n_threads)]
                state.scanners = scanners
                state.dns_total = len(to_resolve)   # store for progress bar
                state.dns_done  = 0
                for s in scanners:
                    s.start()

                print(f"📡 [{session_id[:8]}] DNS resolving {len(to_resolve)} permutations "
                      f"({'resume' if pending_dns is not None else 'fresh'})...")

                # Poll until queue drained OR stop requested
                last_logged_pct = -1
                while work_queue.unfinished_tasks > 0:
                    # Update dns_done from queue progress
                    state.dns_done = state.dns_total - work_queue.unfinished_tasks

                    # Emit a progress log every 10% so the UI shows movement
                    if state.dns_total > 0:
                        pct = int((state.dns_done / state.dns_total) * 100)
                        rounded = (pct // 10) * 10
                        if rounded > last_logged_pct and rounded > 0:
                            last_logged_pct = rounded
                            emit_scan_log(session_id,
                                f"DNS progress: {state.dns_done}/{state.dns_total} ({rounded}%) resolved...",
                                'info')
                    if state.stop_event.is_set():
                        # ── PAUSE during DNS phase ───────────────────────────
                        for s in scanners:
                            s.stop()
                        time.sleep(0.6)   # let in-flight items finish

                        # Drain items still in queue → these were NOT resolved
                        remaining_dns = []
                        while True:
                            try:
                                item = work_queue.get_nowait()
                                work_queue.task_done()
                                remaining_dns.append(item)
                            except queue_module.Empty:
                                break

                        # Items not remaining = were processed (resolved or NXDOMAIN)
                        remaining_ids = {id(p) for p in remaining_dns}
                        resolved_so_far = [
                            p for p in to_resolve
                            if id(p) not in remaining_ids
                            and p.is_registered()
                            and p.get('fuzzer') != '*original'
                        ]

                        state.pending_dns = remaining_dns
                        state.pending_enrich = resolved_so_far

                        _set_db_status(session_id, 'paused', enriched_count)
                        msg = f"Paused during DNS — {len(remaining_dns)} unresolved, {len(resolved_so_far)} queued for enrichment"
                        print(f"⏸  [{session_id[:8]}] " + msg)
                        emit_scan_log(session_id, "DNS resolution engine suspended safely.", 'warning')
                        emit_scan_log(session_id, msg, 'info')
                        return

                    time.sleep(0.1)   # tighter poll → faster completion detection

                for s in scanners:
                    s.stop()

                # All DNS done — collect registered lookalikes
                registered = [
                    p for p in to_resolve
                    if p.is_registered() and p.get('fuzzer') != '*original'
                ]
                state.pending_enrich = registered
                state.pending_dns = []
                msg = f"DNS Phase Complete — {len(registered)} registered lookalikes successfully isolated."
                print(f"✅ [{session_id[:8]}] " + msg)
                emit_scan_log(session_id, msg, 'success')
            else:
                # Resuming directly from enrichment phase (DNS already done)
                registered = pending_enrich
                msg = f"Resuming Phase 2: Enrichment API lookups ({len(registered)} domains remaining)"
                print(f"▶  [{session_id[:8]}] " + msg)
                emit_scan_log(session_id, msg, 'info')

            # ── Phase 2: Enrichment ───────────────────────────────────────────
            state.phase = 'enrichment'
            emit_scan_log(session_id, f"Booting threat enrichment. Initializing WhoIs and VirusTotal payload requests...", 'info')

            # Sort by SLD-level Levenshtein distance (ascending) so the closest
            # visual lookalikes — the highest-risk domains — are always enriched
            # first, even when the total exceeds the cap.
            try:
                registered = sorted(
                    registered,
                    key=lambda p: lev_distance(
                        get_sld(str(p.get('domain', ''))),
                        get_sld(domain)
                    )
                )
            except Exception:
                pass  # non-fatal: fall back to original order

            cap = min(len(registered), 500)

            for i, item in enumerate(registered[:cap]):
                if state.stop_event.is_set():
                    # ── PAUSE during enrichment phase ────────────────────────
                    state.pending_dns = []
                    state.pending_enrich = registered[i:]   # resume from here
                    _set_db_status(session_id, 'paused', enriched_count)
                    msg = f"Paused during enrichment phase — {len(registered) - i} domains pending API verification."
                    print(f"⏸  [{session_id[:8]}] " + msg)
                    emit_scan_log(session_id, "Enrichment routines suspended safely.", 'warning')
                    emit_scan_log(session_id, msg, 'info')
                    return

                try:
                    item_dict = dict(item)
                    enriched = enrich_domain(item_dict, domain)
                    risk = analyze_risk(enriched, domain)

                    # Merge risk explanation into enriched_data so the modal can read it
                    enriched['explanation']   = risk['explanation']
                    enriched['vt_confirmed']  = risk.get('vt_confirmed', False)

                    detected = DetectedDomain(
                        session_id=session_id,          # ← isolated per domain
                        domain=item_dict['domain'],
                        risk_score=risk['risk_score'],
                        risk_status=risk['risk_status'],
                        enriched_data=enriched
                    )
                    db.session.add(detected)
                    enriched_count += 1
                    # Update registered_count every domain so sidebar stays live
                    _set_db_status(session_id, 'running', enriched_count)
                    db.session.commit()
                    
                    status_type = 'error' if risk['risk_status'] == 'Malicious' else 'warning' if risk['risk_status'] == 'Suspicious' else 'success'
                    d_name = item_dict['domain']
                    emit_scan_log(session_id, f"Resolved {d_name} — Score: {risk['risk_score']} [{risk['risk_status'].upper()}]", status_type)
                    
                    # 🔥 NEW: Broadcast pure real-time update to the dashboard
                    try:
                        socketio.emit('scan_update', {
                            'session_id': session_id,
                            'domain': item_dict['domain'],
                            'score': risk['risk_score'],
                            'status': risk['risk_status'],
                            'progress': int((enriched_count / cap) * 100) if cap > 0 else 0,
                            'found': enriched_count,
                            'total': cap
                        })
                    except Exception as e:
                        print(f"[!] Error emitting real-time scan update: {e}")

                    if risk['risk_score'] >= 45:
                        alert = Alert(
                            session_id=session_id,
                            domain=item_dict['domain'],
                            message=f"{risk['risk_status']} (score {risk['risk_score']})",
                            severity='high' if risk['risk_score'] >= 75 else 'medium'
                        )
                        db.session.add(alert)
                        db.session.commit()
                        socketio.emit('new_alert', {
                            'domain': item_dict['domain'],
                            'status': risk['risk_status'],
                            'score': risk['risk_score'],
                            'session_id': session_id
                        })

                    if enriched_count % 10 == 0:
                        msg = f"Enriched {enriched_count}/{cap} domains..."
                        print(f"   [{session_id[:8]}] " + msg)
                        emit_scan_log(session_id, msg, 'info')

                except Exception as domain_err:
                    err_msg = f"Error enriching {item.get('domain', '?')}: {domain_err}"
                    print(f"⚠️  [{session_id[:8]}] " + err_msg)
                    emit_scan_log(session_id, err_msg, 'error')
                    continue

        except Exception as e:
            err_msg = f"Scan engine fatal error: {e}"
            print(f"❌ [{session_id[:8]}] " + err_msg)
            emit_scan_log(session_id, err_msg, 'error')
            traceback.print_exc()

        # ── Scan completed normally ───────────────────────────────────────────
        state.phase = 'done'
        state.pending_dns = []
        state.pending_enrich = []
        _set_db_status(session_id, 'completed', enriched_count)
        msg = f"SCAN COMPLETE — {enriched_count} active threats successfully extracted and vaulted."
        print(f"🎯 [{session_id[:8]}] " + msg)
        emit_scan_log(session_id, msg, 'success')


def _set_db_status(session_id, status, count=None):
    """Helper: update ScanSession in DB (must be called inside app context)."""
    try:
        s = db.session.get(ScanSession, session_id)
        if s:
            s.status = status
            if count is not None:
                s.registered_count = count
            db.session.commit()
    except Exception as e:
        print(f"DB update error: {e}")


# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        from models import User
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if not user.is_approved:
                flash('Account is pending administrator approval.', 'error')
            else:
                login_user(user)
                return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        from models import User
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
        else:
            new_user = User(
                username=username,
                password_hash=generate_password_hash(password),
                is_approved=False,
                is_admin=False
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please wait for an admin to approve your account before logging in.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ─── Page Routes ──────────────────────────────────────────────────────────────

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', active_nav='dashboard', active_tab=0)

@app.route('/alerts')
@login_required
def alerts_page():
    return render_template('dashboard.html', active_nav='alerts', active_tab=2)

@app.route('/reports')
@login_required
def reports_page():
    return render_template('dashboard.html', active_nav='reports', active_tab=3)

@app.route('/admin/users')
@login_required
def admin_users_page():
    if not current_user.is_admin:
        flash('Admin access required.', 'error')
        return redirect(url_for('dashboard'))
    from models import User
    users = User.query.order_by(User.created_at.desc()).all()
    now = datetime.utcnow()
    for u in users:
        # User is online if seen in the last 5 minutes (300 seconds)
        u.is_online = u.last_seen and (now - u.last_seen).total_seconds() < 300
    return render_template('users.html', users=users)

@app.route('/api/admin/users/<int:user_id>/approve', methods=['POST'])
@login_required
def api_approve_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    from models import User
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.is_approved = True
    db.session.commit()
    return jsonify({'success': True, 'message': f'User {user.username} approved.'})

@app.route('/api/admin/users/<int:user_id>/revoke', methods=['POST'])
@login_required
def api_revoke_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot revoke your own access'}), 400
    from models import User
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
    user.is_approved = False
    db.session.commit()
    return jsonify({'success': True, 'message': f'Access for {user.username} revoked.'})

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def api_delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    from models import User
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True, 'message': f'User {user.username} was permanently deleted.'})

# ─── API: Sessions ────────────────────────────────────────────────────────────

@app.route('/api/sessions')
@login_required
def api_sessions():
    sessions = ScanSession.query.filter_by(user_id=current_user.id).order_by(ScanSession.timestamp.desc()).all()
    return jsonify([{
        'id': s.id,
        'domain': s.domain,
        'timestamp': s.timestamp.isoformat(),
        'registered_count': s.registered_count or 0,
        'status': s.status
    } for s in sessions])

# ─── API: Start Scan ──────────────────────────────────────────────────────────

@app.route('/api/scans', methods=['POST'])
@login_required
def api_scan():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing url'}), 400

    domain = data['url'].strip().lower()
    for prefix in ('https://', 'http://'):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split('/')[0]

    # Validate and pre-generate permutations
    try:
        fuzzer = dnstwist.Fuzzer(domain)
        fuzzer.generate()
        all_domains = list(fuzzer.domains)
        raw_count = len(all_domains)

        # ── Smart pre-filter: sort by Levenshtein distance, keep the closest ──
        # Permutations 7+ edits from the original SLD are too different to
        # plausibly fool anyone and massively inflate DNS resolution time.
        # Keeping the 600 closest lookalikes covers all real phishing risk.
        DNS_CAP = 600
        original_sld = get_sld(domain)
        originals = [p for p in all_domains if p.get('fuzzer') == '*original']
        candidates = [p for p in all_domains if p.get('fuzzer') != '*original']

        if len(candidates) > DNS_CAP:
            candidates.sort(
                key=lambda p: lev_distance(
                    get_sld(str(p.get('domain', ''))), original_sld
                )
            )
            candidates = candidates[:DNS_CAP]

        all_domains = originals + candidates
        print(f"🔍 '{domain}' — {raw_count} permutations generated, "
              f"{len(candidates)} kept after Levenshtein pre-filter (cap={DNS_CAP})")
    except Exception as e:
        return jsonify({'error': f'Invalid domain: {str(e)}'}), 400

    session_id = str(uuid.uuid4())
    session = ScanSession(
        id=session_id,
        user_id=current_user.id,
        domain=domain,
        status='running',
        total_permutations=len(all_domains)   # store for progress bar
    )
    db.session.add(session)
    db.session.commit()

    state = ScanState(domain)
    state.all_domains = all_domains
    active_scans[session_id] = state

    threading.Thread(
        target=_do_scan,
        args=(session_id, domain),
        daemon=True
    ).start()

    return jsonify({'id': session_id, 'status': 'started', 'domain': domain})

# ─── API: Pause Scan ──────────────────────────────────────────────────────────

@app.route('/api/scans/<sid>/pause', methods=['POST'])
def api_pause_scan(sid):
    state = active_scans.get(sid)
    if not state:
        return jsonify({'error': 'No active scan for this session'}), 404

    s = db.session.get(ScanSession, sid)
    if not s or s.status not in ('running',):
        return jsonify({'error': f'Scan is not running (status: {s.status if s else "?"})'}) , 400

    state.stop_event.set()
    return jsonify({'status': 'pausing', 'message': 'Scan will pause after current item'})

# ─── API: Resume Scan ─────────────────────────────────────────────────────────

@app.route('/api/scans/<sid>/resume', methods=['POST'])
def api_resume_scan(sid):
    state = active_scans.get(sid)
    s = db.session.get(ScanSession, sid)

    if not s:
        return jsonify({'error': 'Session not found'}), 404
    if s.status != 'paused':
        return jsonify({'error': f'Scan is not paused (status: {s.status})'}), 400
    if not state:
        return jsonify({'error': 'No saved scan state (cannot resume)'}), 404

    # Clear stop signal, update DB, start new worker thread
    state.stop_event.clear()
    _set_db_status(sid, 'running')

    pending_dns = state.pending_dns[:]          # copy to avoid race
    pending_enrich = state.pending_enrich[:]

    # Choose resume entry point
    if pending_enrich and not pending_dns:
        # DNS complete, resuming enrichment
        threading.Thread(
            target=_do_scan,
            args=(sid, state.domain),
            kwargs={'pending_enrich': pending_enrich},
            daemon=True
        ).start()
    else:
        # DNS not complete, resume from remaining DNS items;
        # pass already-resolved ones so they're enriched after DNS finishes
        threading.Thread(
            target=_do_scan,
            args=(sid, state.domain),
            kwargs={
                'pending_dns': pending_dns,
                'pending_enrich': pending_enrich if pending_enrich else None
            },
            daemon=True
        ).start()

    return jsonify({'status': 'resumed', 'message': 'Scan resumed from checkpoint'})

# ─── API: Reset Scan ──────────────────────────────────────────────────────────

@app.route('/api/scans/<sid>/reset', methods=['POST'])
def api_reset_scan(sid):
    from sqlalchemy import text as sa_text

    # 1. Signal stop immediately (non-blocking)
    state = active_scans.pop(sid, None)
    if state:
        state.stop_event.set()
        for s in getattr(state, 'scanners', []):
            try: s.stop()
            except Exception: pass

    # 2. Delete using raw SQL with its own connection + retry back-off.
    #    Raw SQL bypasses ORM session cache and is immune to SQLAlchemy
    #    "DetachedInstanceError" / session state issues.
    last_err = None
    for attempt in range(10):
        try:
            with db.engine.connect() as conn:
                conn.execute(sa_text('DELETE FROM alert WHERE session_id = :sid'), {'sid': sid})
                conn.execute(sa_text('DELETE FROM detected_domain WHERE session_id = :sid'), {'sid': sid})
                conn.execute(sa_text('DELETE FROM scan_session WHERE id = :sid'), {'sid': sid})
                conn.commit()
            last_err = None
            break
        except Exception as e:
            last_err = str(e)
            time.sleep(0.15 * (attempt + 1))   # 0.15s → 0.3s → … → 1.5s

    if last_err:
        return jsonify({'error': f'DB reset failed: {last_err}'}), 500

    return jsonify({'status': 'reset', 'message': 'Session cleared'})


# ─── API: Results ─────────────────────────────────────────────────────────────

@app.route('/api/scans/<sid>/domains')
def api_domains(sid):
    results = DetectedDomain.query.filter_by(session_id=sid).all()
    return jsonify([{
        'domain': d.domain,
        'risk_status': d.risk_status,
        'risk_score': d.risk_score,
        'risk_emoji': '🔴' if d.risk_status == 'Malicious' else '🟠' if d.risk_status == 'Suspicious' else '🟢',
        'age_days': d.enriched_data.get('whois', {}).get('age_days') if d.enriched_data else None,
        'web_title': (
            (d.enriched_data.get('web', {}).get('https', {}).get('title') or
             d.enriched_data.get('web', {}).get('http', {}).get('title') or '—')[:60]
        ) if d.enriched_data else '—',
        'ip': (d.enriched_data.get('dns_a') or ['—'])[0]
              if (d.enriched_data and isinstance(d.enriched_data.get('dns_a'), list)
                  and d.enriched_data.get('dns_a')) else '—',
        # VirusTotal summary for table badge
        'vt_malicious':  (d.enriched_data or {}).get('virustotal', {}).get('malicious', 0),
        'vt_suspicious': (d.enriched_data or {}).get('virustotal', {}).get('suspicious', 0),
        'vt_available':  (d.enriched_data or {}).get('virustotal', {}).get('available', False),
    } for d in results])


@app.route('/api/scans/<sid>/domains/<path:domain_name>')
def api_domain_detail(sid, domain_name):
    """Return complete enriched data for one domain (used by the detail modal)."""
    d = DetectedDomain.query.filter_by(session_id=sid, domain=domain_name).first()
    if not d:
        return jsonify({'error': 'Domain not found in this session'}), 404

    ed = d.enriched_data or {}
    vt = ed.get('virustotal', {})

    return jsonify({
        'domain':        d.domain,
        'risk_status':   d.risk_status,
        'risk_score':    d.risk_score,
        'risk_emoji':    '🔴' if d.risk_status == 'Malicious' else '🟠' if d.risk_status == 'Suspicious' else '🟢',
        'timestamp':     d.timestamp.isoformat(),
        # WHOIS
        'whois': {
            'registrar':       ed.get('whois', {}).get('registrar', '—'),
            'creation_date':   ed.get('whois', {}).get('creation_date', '—'),
            'expiration_date': ed.get('whois', {}).get('expiration_date', '—'),
            'age_days':        ed.get('whois', {}).get('age_days'),
        },
        # SSL
        'ssl': {
            'valid':   ed.get('ssl', {}).get('valid', False),
            'issuer':  ed.get('ssl', {}).get('issuer', '—'),
            'expires': ed.get('ssl', {}).get('expires', '—'),
        },
        # DNS
        'dns_a':   ed.get('dns_a', []),
        'dns_mx':  ed.get('dns_mx', []),
        'dns_ns':  ed.get('dns_ns', []),
        'fuzzer':  ed.get('fuzzer', '—'),
        # Web
        'web': {
            'https_status': ed.get('web', {}).get('https', {}).get('status'),
            'https_title':  ed.get('web', {}).get('https', {}).get('title', '—'),
            'https_url':    ed.get('web', {}).get('https', {}).get('final_url', '—'),
            'http_status':  ed.get('web', {}).get('http', {}).get('status'),
        },
        # VirusTotal
        'virustotal': {
            'available':        vt.get('available', False),
            'reason':           vt.get('reason', ''),
            'malicious':        vt.get('malicious', 0),
            'suspicious':       vt.get('suspicious', 0),
            'harmless':         vt.get('harmless', 0),
            'undetected':       vt.get('undetected', 0),
            'engines_total':    vt.get('engines_total', 0),
            'community_score':  vt.get('community_score', 0),
            'flagging_engines': vt.get('flagging_engines', []),
            'vt_link':          vt.get('vt_link', f'https://www.virustotal.com/gui/domain/{d.domain}'),
        },
        # Risk breakdown
        'explanation': ed.get('explanation', '—'),
    })

@app.route('/api/scans/<sid>/status')
def api_scan_status(sid):
    s = db.session.get(ScanSession, sid)
    if not s:
        return jsonify({'error': 'Session not found'}), 404
    state = active_scans.get(sid)
    total  = s.total_permutations or 0
    done   = s.registered_count or 0

    # Use live dns_done counter tracked by the scan thread
    dns_done  = state.dns_done  if state else 0
    dns_total = state.dns_total if state else total

    if state and state.phase == 'dns' and dns_total > 0:
        progress_pct = round((dns_done / dns_total) * 50, 1)   # DNS = first 50%
    elif state and state.phase == 'enrichment' and total > 0:
        enrich_cap   = min(len(state.pending_enrich) + done, total) if state.pending_enrich else total
        phase_progress = min(done / max(enrich_cap, 1), 1.0)
        progress_pct = round(50 + phase_progress * 50, 1)        # Enrichment = second 50%
    elif s.status == 'completed':
        progress_pct = 100.0
    else:
        progress_pct = 0.0

    return jsonify({
        'status':             s.status,
        'domain':             s.domain,
        'registered_count':   done,
        'total_permutations': total,
        'progress_pct':       progress_pct,
        'phase':              state.phase if state else 'done',
        'dns_done':           dns_done,
        'dns_total':          dns_total or total,
        'pending_dns':        len(state.pending_dns) if state else 0,
        'pending_enrich':     len(state.pending_enrich) if state else 0,
    })

@app.route('/api/scans/<sid>/csv')
def api_csv(sid):
    results = DetectedDomain.query.filter_by(session_id=sid).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Domain', 'Risk Status', 'Risk Score', 'IP', 'Age Days', 'Web Title'])
    for d in results:
        ed = d.enriched_data or {}
        writer.writerow([
            d.domain, d.risk_status, d.risk_score,
            (ed.get('dns_a') or ['—'])[0] if isinstance(ed.get('dns_a'), list) else '—',
            ed.get('whois', {}).get('age_days', '—'),
            (ed.get('web', {}).get('https', {}).get('title') or
             ed.get('web', {}).get('http', {}).get('title') or '—')[:60]
        ])
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': f'attachment; filename=phishguard_{sid[:8]}.csv'})

@app.route('/api/scans/<sid>/json')
def api_json(sid):
    results = DetectedDomain.query.filter_by(session_id=sid).all()
    payload = [{'domain': d.domain, 'risk_status': d.risk_status,
                'risk_score': d.risk_score, 'timestamp': d.timestamp.isoformat(),
                'enriched_data': d.enriched_data} for d in results]
    return Response(json.dumps(payload, indent=2, default=str), mimetype='application/json',
                    headers={'Content-Disposition': f'attachment; filename=phishguard_{sid[:8]}.json'})

# ─── API: Dashboard ───────────────────────────────────────────────────────────

@app.route('/api/dashboard')
@login_required
def api_dashboard():
    # Only view domains/alerts from scans owned by the current user!
    user_session_ids = [s.id for s in ScanSession.query.filter_by(user_id=current_user.id).all()]
    
    if not user_session_ids:
        return jsonify({
            'risk_overview': {'safe': 0, 'suspicious': 0, 'malicious': 0},
            'detected_domains': [],
            'recent_alerts': []
        })

    safe = DetectedDomain.query.filter(DetectedDomain.session_id.in_(user_session_ids), DetectedDomain.risk_status == 'Safe').count()
    suspicious = DetectedDomain.query.filter(DetectedDomain.session_id.in_(user_session_ids), DetectedDomain.risk_status == 'Suspicious').count()
    malicious = DetectedDomain.query.filter(DetectedDomain.session_id.in_(user_session_ids), DetectedDomain.risk_status == 'Malicious').count()
    return jsonify({
        'risk_overview': {'safe': safe, 'suspicious': suspicious, 'malicious': malicious},
        'detected_domains': [
            {'domain': d.domain, 'risk_status': d.risk_status,
             'risk_score': d.risk_score, 'timestamp': d.timestamp.isoformat()}
            for d in DetectedDomain.query.filter(DetectedDomain.session_id.in_(user_session_ids))
                            .order_by(DetectedDomain.timestamp.desc()).limit(20).all()
        ],
        'recent_alerts': [
            {'domain': a.domain, 'message': a.message, 'severity': a.severity}
            for a in Alert.query.filter(Alert.session_id.in_(user_session_ids))
                         .order_by(Alert.timestamp.desc()).limit(10).all()
        ]
    })

# ─── SocketIO ─────────────────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    emit('status', {'message': 'Connected to PhishGuard'})

# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("🚀 PhishGuard started → http://127.0.0.1:8000")
    socketio.run(app, host='127.0.0.1', port=8000, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)