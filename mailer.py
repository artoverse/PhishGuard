"""
mailer.py — PhishGuard Email Alert System
Uses Python's built-in smtplib: no extra dependencies required.
All sends happen in a daemon background thread so they NEVER block scans.
"""

import smtplib
import threading
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


# ── HTML template ─────────────────────────────────────────────────────────────

_EMAIL_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard Threat Alert</title>
<style>
  body {{
    margin: 0; padding: 0; background: #0f172a;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    color: #e2e8f0;
  }}
  .wrapper {{ max-width: 640px; margin: 0 auto; padding: 32px 16px; }}
  .header {{
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid #334155; border-radius: 16px;
    padding: 32px; margin-bottom: 24px; text-align: center;
  }}
  .header .logo {{
    display: inline-block; background: #dc2626; color: #fff;
    font-weight: 800; font-size: 18px; padding: 10px 18px;
    border-radius: 12px; letter-spacing: -0.02em; margin-bottom: 16px;
  }}
  .header h1 {{ margin: 0; font-size: 22px; font-weight: 700; color: #f1f5f9; }}
  .header p {{ margin: 8px 0 0; color: #94a3b8; font-size: 14px; }}
  .summary-grid {{
    display: grid; grid-template-columns: 1fr 1fr;
    gap: 12px; margin-bottom: 24px;
  }}
  .summary-card {{
    border-radius: 12px; padding: 20px; text-align: center; border: 1px solid;
  }}
  .card-malicious {{ background: rgba(220,38,38,0.1); border-color: rgba(220,38,38,0.3); }}
  .card-suspicious {{ background: rgba(245,158,11,0.1); border-color: rgba(245,158,11,0.3); }}
  .card-malicious .num {{ color: #f87171; font-size: 36px; font-weight: 800; margin: 0; }}
  .card-suspicious .num {{ color: #fbbf24; font-size: 36px; font-weight: 800; margin: 0; }}
  .card-label {{ font-size: 11px; font-weight: 600; letter-spacing: 0.1em;
                text-transform: uppercase; color: #94a3b8; margin-top: 4px; }}
  .section-title {{
    font-size: 11px; font-weight: 600; letter-spacing: 0.1em;
    text-transform: uppercase; color: #64748b; margin: 0 0 12px;
  }}
  table {{ width: 100%; border-collapse: collapse; border-radius: 12px; overflow: hidden; }}
  th {{
    background: #1e293b; color: #64748b; font-size: 11px; font-weight: 600;
    letter-spacing: 0.05em; text-transform: uppercase;
    padding: 12px 16px; text-align: left;
  }}
  td {{ padding: 12px 16px; border-bottom: 1px solid #1e293b; font-size: 13px; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:nth-child(odd) td {{ background: #0f172a; }}
  tr:nth-child(even) td {{ background: #111827; }}
  .badge {{
    display: inline-block; padding: 2px 10px; border-radius: 999px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.04em;
  }}
  .badge-malicious {{ background: rgba(220,38,38,0.2); color: #f87171; }}
  .badge-suspicious {{ background: rgba(245,158,11,0.2); color: #fbbf24; }}
  .badge-safe {{ background: rgba(16,185,129,0.2); color: #34d399; }}
  .footer {{
    margin-top: 24px; padding: 20px; background: #1e293b;
    border-radius: 12px; border: 1px solid #334155; text-align: center;
  }}
  .footer p {{ margin: 4px 0; font-size: 12px; color: #64748b; }}
  .footer a {{ color: #60a5fa; text-decoration: none; }}
  .domain-font {{ font-family: 'Menlo', 'Consolas', monospace; }}
  .ip-font {{ font-family: 'Menlo', 'Consolas', monospace; color: #94a3b8; }}
</style>
</head>
<body>
<div class="wrapper">

  <!-- Header -->
  <div class="header">
    <div class="logo">PG PhishGuard</div>
    <h1>⚠️ Threat Alert: {domain}</h1>
    <p>Scan completed at {scan_time} UTC</p>
  </div>

  <!-- Summary Cards -->
  <div class="summary-grid">
    <div class="summary-card card-malicious">
      <p class="num">{malicious_count}</p>
      <div class="card-label">Malicious</div>
    </div>
    <div class="summary-card card-suspicious">
      <p class="num">{suspicious_count}</p>
      <div class="card-label">Suspicious</div>
    </div>
  </div>

  <!-- Threats Table -->
  <p class="section-title">Detected Phishing Domains ({total_shown} shown)</p>
  <table>
    <thead>
      <tr>
        <th>Domain</th>
        <th>Risk</th>
        <th>Score</th>
        <th>IP</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <!-- Footer -->
  <div class="footer">
    <p>🛡️ PhishGuard Automated Threat Intelligence</p>
    <p>Domain monitored: <strong style="color:#e2e8f0">{domain}</strong></p>
    <p style="margin-top:8px">
      <a href="http://127.0.0.1:8000/dashboard">View Full Dashboard →</a>
    </p>
    <p style="margin-top:8px; color:#475569; font-size:11px">
      This alert was generated automatically. Do not reply to this email.
    </p>
  </div>

</div>
</body>
</html>"""

_ROW_TEMPLATE = """
<tr>
  <td class="domain-font">{domain}</td>
  <td><span class="badge badge-{badge_class}">{risk_status}</span></td>
  <td style="font-weight:600; color:{score_color}">{risk_score}</td>
  <td class="ip-font">{ip}</td>
</tr>"""


def _build_html(domain: str, threats: List[Dict[str, Any]],
                malicious_only: bool = False) -> str:
    """Render the HTML email body."""
    malicious = [t for t in threats if t.get('risk_status') == 'Malicious']
    suspicious = [t for t in threats if t.get('risk_status') == 'Suspicious']

    # Sort by score descending
    display = sorted(threats, key=lambda x: x.get('risk_score', 0), reverse=True)
    if malicious_only:
        display = [t for t in display if t.get('risk_status') == 'Malicious']

    MAX_ROWS = 50   # cap so the email doesn't become a wall of text
    shown = display[:MAX_ROWS]

    rows_html = ''
    for t in shown:
        status = t.get('risk_status', 'Unknown')
        score  = t.get('risk_score', 0)
        badge_class = (
            'malicious' if status == 'Malicious' else
            'suspicious' if status == 'Suspicious' else 'safe'
        )
        score_color = (
            '#f87171' if status == 'Malicious' else
            '#fbbf24' if status == 'Suspicious' else '#34d399'
        )
        enriched = t.get('enriched_data') or {}
        ip_str = (enriched.get('dns_a') or ['—'])[0] if enriched.get('dns_a') else '—'

        rows_html += _ROW_TEMPLATE.format(
            domain=t.get('domain', '—'),
            badge_class=badge_class,
            risk_status=status,
            risk_score=score,
            score_color=score_color,
            ip=ip_str,
        )

    return _EMAIL_TEMPLATE.format(
        domain=domain,
        scan_time=datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        malicious_count=len(malicious),
        suspicious_count=len(suspicious),
        total_shown=len(shown),
        rows=rows_html or '<tr><td colspan="4" style="text-align:center;color:#64748b;padding:24px">No threats to display</td></tr>',
    )


def _build_text(domain: str, threats: List[Dict[str, Any]]) -> str:
    """Plain-text fallback."""
    malicious = sum(1 for t in threats if t.get('risk_status') == 'Malicious')
    suspicious = sum(1 for t in threats if t.get('risk_status') == 'Suspicious')
    lines = [
        f"PhishGuard Threat Alert: {domain}",
        f"Scan completed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        f"Malicious: {malicious}  |  Suspicious: {suspicious}",
        "",
        "TOP THREATS:",
    ]
    for t in sorted(threats, key=lambda x: x.get('risk_score', 0), reverse=True)[:30]:
        lines.append(f"  [{t.get('risk_status','?'):10}] {t.get('risk_score',0):5.1f}  {t.get('domain','—')}")
    lines += ["", "View dashboard: http://127.0.0.1:8000/dashboard"]
    return "\n".join(lines)


# ── Public API ─────────────────────────────────────────────────────────────────

def send_threat_alert(
    to_email: str,
    session_domain: str,
    threats: List[Dict[str, Any]],
    smtp_config: Dict[str, Any],
    malicious_only: bool = False,
    subject_prefix: str = "⚠️ PhishGuard Alert",
) -> None:
    """
    Send a threat-digest email in a background thread.
    Never raises — all errors are logged and swallowed so scans keep running.

    Args:
        to_email:       Recipient address.
        session_domain: The original domain that was scanned.
        threats:        List of dicts with risk_status / risk_score / domain / enriched_data.
        smtp_config:    Dict with keys: server, port, username, password, from_email, use_tls.
        malicious_only: If True only Malicious rows appear in the table.
        subject_prefix: Email subject prefix.
    """
    def _send():
        try:
            _do_send(to_email, session_domain, threats, smtp_config,
                     malicious_only, subject_prefix)
        except Exception as exc:
            logger.error("[mailer] Unexpected error sending alert for %s: %s",
                         session_domain, exc, exc_info=True)

    t = threading.Thread(target=_send, daemon=True, name=f"mailer-{session_domain}")
    t.start()


def _do_send(
    to_email: str,
    session_domain: str,
    threats: List[Dict[str, Any]],
    smtp_config: Dict[str, Any],
    malicious_only: bool,
    subject_prefix: str,
) -> None:
    """Blocking send — called from background thread only."""
    server   = smtp_config.get('server', '')
    port     = int(smtp_config.get('port', 587))
    username = smtp_config.get('username', '')
    password = smtp_config.get('password', '')
    from_email = smtp_config.get('from_email') or username
    use_tls  = smtp_config.get('use_tls', True)

    if not (server and username and password):
        logger.warning("[mailer] SMTP not configured — skipping email alert for %s", session_domain)
        return

    malicious_count = sum(1 for t in threats if t.get('risk_status') == 'Malicious')
    suspicious_count = sum(1 for t in threats if t.get('risk_status') == 'Suspicious')
    subject = f"{subject_prefix}: {session_domain} — {malicious_count} Malicious, {suspicious_count} Suspicious"

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = from_email          # plain address — Gmail rejects display-name formats
    msg['To']      = to_email
    msg['Reply-To'] = from_email
    msg['X-Mailer'] = 'PhishGuard/1.0'

    html_body = _build_html(session_domain, threats, malicious_only)
    text_body = _build_text(session_domain, threats)

    msg.attach(MIMEText(text_body, 'plain', 'utf-8'))
    msg.attach(MIMEText(html_body, 'html',  'utf-8'))

    logger.info("[mailer] Sending alert for %s → %s via %s:%s", session_domain, to_email, server, port)
    try:
        with smtplib.SMTP(server, port, timeout=15) as smtp_conn:
            if use_tls:
                smtp_conn.starttls()
            smtp_conn.login(username, password)
            smtp_conn.sendmail(from_email, [to_email], msg.as_bytes())
        logger.info("[mailer] ✅ Alert sent successfully for %s → %s", session_domain, to_email)
    except smtplib.SMTPAuthenticationError:
        logger.error("[mailer] SMTP authentication failed — check MAIL_USERNAME / MAIL_PASSWORD in .env")
    except smtplib.SMTPConnectError as e:
        logger.error("[mailer] Cannot connect to SMTP server %s:%s — %s", server, port, e)
    except smtplib.SMTPRecipientsRefused as e:
        # e.recipients is a dict: {address: (code, msg)}
        details = '; '.join(f"{addr}: {msg}" for addr, (code, msg) in e.recipients.items())
        logger.error("[mailer] Recipient refused: %s — %s", to_email, details)
    except Exception as e:
        logger.error("[mailer] Send failed for %s: %s", session_domain, e)


def send_test_email(to_email: str, smtp_config: Dict[str, Any]) -> dict:
    """
    Synchronous test-email send (called from API endpoint).
    Returns {'ok': True} or {'ok': False, 'error': str}.
    """
    server   = smtp_config.get('server', '')
    port     = int(smtp_config.get('port', 587))
    username = smtp_config.get('username', '')
    password = smtp_config.get('password', '')
    from_email = smtp_config.get('from_email') or username
    use_tls  = smtp_config.get('use_tls', True)

    if not (server and username and password):
        return {'ok': False, 'error': 'SMTP not configured in .env (need MAIL_SERVER, MAIL_USERNAME, MAIL_PASSWORD)'}

    html = """<div style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;padding:40px;border-radius:16px">
        <div style="background:#dc2626;color:#fff;font-weight:800;display:inline-block;padding:8px 16px;border-radius:10px;margin-bottom:16px">PG PhishGuard</div>
        <h2 style="margin:0 0 12px">✅ Test Email Successful</h2>
        <p style="color:#94a3b8">Your SMTP configuration is working correctly. PhishGuard will now send threat alerts to this address when scans detect malicious domains.</p>
    </div>"""

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'PhishGuard - SMTP Test Successful'
    msg['From']    = from_email          # plain address only — avoids Gmail display-name rejection
    msg['To']      = to_email
    msg['Reply-To'] = from_email

    msg.attach(MIMEText("PhishGuard SMTP test — configuration is working.", 'plain'))
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(server, port, timeout=10) as smtp_conn:
            if use_tls:
                smtp_conn.starttls()
            smtp_conn.login(username, password)
            smtp_conn.sendmail(from_email, [to_email], msg.as_bytes())
        return {'ok': True}
    except smtplib.SMTPAuthenticationError:
        return {'ok': False, 'error': 'SMTP authentication failed — check username/password (Gmail: use App Password)'}
    except smtplib.SMTPConnectError as e:
        return {'ok': False, 'error': f'Cannot connect to {server}:{port} — {e}'}
    except smtplib.SMTPRecipientsRefused as e:
        # Surface the actual SMTP code + message from Gmail
        details = '; '.join(
            f"{addr}: [{code}] {msg.decode() if isinstance(msg, bytes) else msg}"
            for addr, (code, msg) in e.recipients.items()
        )
        return {'ok': False, 'error': f'Recipient refused by Gmail — {details}'}
    except Exception as e:
        return {'ok': False, 'error': str(e)}

