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

_LIVE_ALERT_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PhishGuard — Live Threat Update</title>
</head>
<body style="margin:0;padding:0;background:#0f172a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:520px;margin:0 auto;padding:32px 16px;">

  <!-- Header Bar -->
  <div style="background:linear-gradient(135deg,#e11d48,#be123c);border-radius:16px;padding:28px 32px;margin-bottom:20px;text-align:center;">
    <div style="display:inline-block;background:rgba(0,0,0,0.2);border-radius:10px;padding:6px 14px;font-size:11px;font-weight:700;color:#fecdd3;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:14px;">🚨 Live Scan Alert</div>
    <h1 style="margin:0;font-size:22px;font-weight:800;color:#fff;">Malicious Threat Found</h1>
    <p style="margin:8px 0 0;color:rgba(255,255,255,0.8);font-size:13px;">Scanning <strong style="color:#fff;">{session_domain}</strong></p>
  </div>

  <!-- Latest Threat Card -->
  <div style="background:#1e293b;border:1px solid #334155;border-radius:16px;padding:24px 32px;margin-bottom:16px;">
    <div style="font-size:11px;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;color:#cbd5e1;margin-bottom:12px;">Just Detected</div>
    <div style="font-family:'Menlo','Consolas',monospace;font-size:18px;font-weight:700;color:#f87171;word-break:break-all;">{latest_threat_domain}</div>
  </div>

  <!-- Threat List -->
  <div style="background:#1e293b;border:1px solid #334155;border-radius:16px;padding:20px 32px;margin-bottom:20px;">
    <div style="font-size:11px;font-weight:600;letter-spacing:0.1em;text-transform:uppercase;color:#94a3b8;margin-bottom:12px;">All Malicious Found So Far ({threat_count})</div>
    <table width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
      {threat_list_html}
    </table>
  </div>

  <!-- Info Box -->
  <div style="background:#1e293b;border:1px solid #334155;border-radius:12px;padding:18px 24px;margin-bottom:20px;">
    <p style="margin:0;font-size:13px;color:#94a3b8;line-height:1.6;">
      PhishGuard is actively scanning <strong style="color:#e2e8f0;">{session_domain}</strong> for phishing domains.<br><br>
      <strong style="color:#e2e8f0;">A full threat digest</strong> will be sent automatically when the scan completes.
    </p>
  </div>

  <!-- CTA -->
  <div style="text-align:center;margin-bottom:24px;">
    <a href="http://127.0.0.1:8000/dashboard"
       style="display:inline-block;background:#e11d48;color:#fff;text-decoration:none;font-weight:700;font-size:14px;padding:12px 28px;border-radius:12px;">
      View Live Dashboard →
    </a>
  </div>

  <!-- Footer -->
  <p style="text-align:center;font-size:11px;color:#475569;margin:0;">
    🛡️ PhishGuard Automated Threat Intelligence · Do not reply to this email
  </p>

</div>
</body>
</html>"""


def send_live_threat_alert(
    to_email: str,
    session_domain: str,
    latest_threat_domain: str,
    threats: List[Dict[str, Any]],
    smtp_config: Dict[str, Any],
) -> None:
    """
    Fire a live 'during scan' email whenever a new malicious domain is found,
    showing all malicious domains discovered so far.
    Runs in a daemon background thread — never blocks the scan worker.
    """
    
    threat_list_html = ""
    for idx, t in enumerate(threats[:20]): # Caps at 20 to avoid massive emails during scans
        domain = t.get('domain', '')
        score = t.get('risk_score', 0)
        # Highlight the newest one
        bg_col = '#334155' if domain == latest_threat_domain else 'transparent'
        
        threat_list_html += f"""
        <tr>
            <td valign="middle" style="padding:10px 0;background-color:{bg_col};font-family:'Menlo','Consolas',monospace;font-size:13px;color:#e2e8f0;word-break:break-all;border-bottom:1px solid rgba(255,255,255,0.05);">
                <span style="padding-left:12px;">{domain}</span>
            </td>
            <td align="right" valign="middle" style="padding:10px 0;background-color:{bg_col};font-size:13px;font-weight:700;color:#f87171;border-bottom:1px solid rgba(255,255,255,0.05);white-space:nowrap;">
                <span style="padding-right:12px;">{score}</span>
            </td>
        </tr>
        """
        
    if len(threats) > 20:
        threat_list_html += f"""
        <tr>
            <td colspan="2" align="center" style="padding-top:12px;font-size:12px;color:#64748b;">
                + {len(threats) - 20} more... (see dashboard or final digest)
            </td>
        </tr>
        """

    html = _LIVE_ALERT_HTML.format(
        session_domain=session_domain,
        latest_threat_domain=latest_threat_domain,
        threat_count=len(threats),
        threat_list_html=threat_list_html,
    )
    
    plain_list = "\n".join([f" - {t.get('domain')} (Score: {t.get('risk_score')})" for t in threats[:20]])
    if len(threats) > 20:
        plain_list += f"\n ... and {len(threats) - 20} more."

    plain = (
        f"PhishGuard — Live Threat Update\n"
        f"Scanning: {session_domain}\n\n"
        f"Just Detected: {latest_threat_domain}\n\n"
        f"All Malicious Found So Far ({len(threats)}):\n"
        f"{plain_list}\n\n"
        f"A full threat digest will be emailed when the scan completes.\n"
        f"Dashboard: http://127.0.0.1:8000/dashboard"
    )

    def _send():
        server   = smtp_config.get('server', '')
        port     = int(smtp_config.get('port', 587))
        username = smtp_config.get('username', '')
        password = smtp_config.get('password', '')
        from_email = smtp_config.get('from_email') or username

        if not (server and username and password):
            logger.warning("[mailer] SMTP not configured — skipping live threat alert")
            return

        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"🚨 PhishGuard — New Malicious Threat: {latest_threat_domain}"
        msg['From']    = from_email
        msg['To']      = to_email

        msg.attach(MIMEText(plain, 'plain', 'utf-8'))
        msg.attach(MIMEText(html,  'html',  'utf-8'))

        try:
            with smtplib.SMTP(server, port, timeout=15) as s:
                if smtp_config.get('use_tls', True):
                    s.starttls()
                s.login(username, password)
                s.sendmail(from_email, [to_email], msg.as_bytes())
            logger.info("[mailer] 🚨 Live threat alert sent → %s", to_email)
        except Exception as e:
            logger.error("[mailer] Live threat alert failed: %s", e)

    threading.Thread(target=_send, daemon=True, name=f"live-alert-{session_domain}").start()


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

_BRAND_ALERT_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<div style="max-width:560px;margin:32px auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.10);">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#dc2626,#b91c1c);padding:32px 36px;">
    <div style="background:rgba(255,255,255,0.15);display:inline-block;border-radius:8px;padding:4px 12px;font-size:11px;font-weight:700;color:#fecaca;letter-spacing:0.08em;text-transform:uppercase;margin-bottom:14px;">🚨 Brand Impersonation Alert</div>
    <h1 style="margin:0;font-size:22px;font-weight:800;color:#ffffff;line-height:1.3;">Your Brand Is Being Impersonated</h1>
    <p style="margin:10px 0 0;color:rgba(255,255,255,0.85);font-size:14px;">
      PhishGuard has detected an active phishing domain targeting <strong style="color:#fff;">{brand_domain}</strong>
    </p>
  </div>

  <!-- Body -->
  <div style="padding:32px 36px;">
    <p style="margin:0 0 20px;color:#475569;font-size:14px;line-height:1.7;">
      Dear <strong>{brand_domain}</strong> Security Team,
    </p>
    <p style="margin:0 0 20px;color:#475569;font-size:14px;line-height:1.7;">
      Our automated Threat Intelligence Platform, <strong>PhishGuard</strong>, has identified the following domain actively impersonating your brand to harvest user credentials:
    </p>

    <!-- Threat Card -->
    <div style="background:#fef2f2;border:1px solid #fecaca;border-left:4px solid #dc2626;border-radius:8px;padding:20px 24px;margin-bottom:24px;">
      <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#991b1b;margin-bottom:8px;">Detected Phishing Domain</div>
      <div style="font-family:'Menlo','Consolas',monospace;font-size:18px;font-weight:700;color:#dc2626;word-break:break-all;">{phishing_domain}</div>
      <div style="margin-top:12px;display:flex;gap:16px;">
        <div>
          <div style="font-size:11px;color:#6b7280;margin-bottom:2px;">Risk Score</div>
          <div style="font-size:16px;font-weight:700;color:#dc2626;">{risk_score}/100</div>
        </div>
        <div>
          <div style="font-size:11px;color:#6b7280;margin-bottom:2px;">Classification</div>
          <div style="font-size:16px;font-weight:700;color:#dc2626;">{risk_status}</div>
        </div>
      </div>
    </div>

    <p style="margin:0 0 16px;color:#475569;font-size:14px;line-height:1.7;">
      This domain exhibits characteristics consistent with active phishing infrastructure — including structural similarities to your brand name, credential harvesting forms, and registration patterns associated with disposable phishing campaigns.
    </p>
    <p style="margin:0 0 16px;color:#475569;font-size:14px;line-height:1.7;">
      We recommend your security team investigate and consider filing a takedown request with the domain registrar immediately to protect your users.
    </p>

    <p style="margin:0;color:#94a3b8;font-size:13px;">This is an automated alert sent by the <strong>PhishGuard Threat Intelligence Platform</strong>.</p>
  </div>

  <!-- Footer -->
  <div style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 36px;text-align:center;">
    <p style="margin:0;font-size:11px;color:#94a3b8;">PhishGuard SOC &bull; Automated Brand Protection Alert</p>
  </div>

</div>
</body>
</html>"""


def send_brand_notification(brand_domain: str, phishing_domain: str, risk_score: float,
                            risk_status: str, security_emails: List[str], smtp_config: Dict[str, Any]) -> dict:
    """
    Notifies the real brand owner that a phishing domain is impersonating them.
    Emails are sent to the brand domain's security/abuse contacts.
    """
    server     = smtp_config.get('server', '')
    port       = int(smtp_config.get('port', 587))
    username   = smtp_config.get('username', '')
    password   = smtp_config.get('password', '')
    from_email = smtp_config.get('from_email') or username
    use_tls    = smtp_config.get('use_tls', True)

    if not (server and username and password):
        return {'ok': False, 'error': 'SMTP not configured in .env'}

    if not security_emails:
        return {'ok': False, 'error': 'No security contact email found for the brand domain'}

    html = _BRAND_ALERT_HTML.format(
        brand_domain=brand_domain,
        phishing_domain=phishing_domain,
        risk_score=risk_score,
        risk_status=risk_status,
    )

    plain = (
        f"Brand Impersonation Alert — {brand_domain}\n\n"
        f"PhishGuard has detected an active phishing domain impersonating your brand:\n"
        f"  Domain : {phishing_domain}\n"
        f"  Score  : {risk_score}/100 ({risk_status})\n\n"
        f"Please investigate and consider filing a takedown with the domain registrar.\n\n"
        f"-- PhishGuard Threat Intelligence Platform"
    )

    to_address = ", ".join(security_emails)

    msg = MIMEMultipart('alternative')
    msg['Subject'] = f'[PhishGuard Alert] Brand Impersonation Detected — {phishing_domain}'
    msg['From']    = from_email
    msg['To']      = to_address
    msg['Reply-To'] = from_email

    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(server, port, timeout=10) as smtp_conn:
            if use_tls:
                smtp_conn.starttls()
            smtp_conn.login(username, password)
            smtp_conn.sendmail(from_email, security_emails, msg.as_bytes())
        logger.info("[mailer] Brand alert dispatched for %s → %s", phishing_domain, to_address)
        return {'ok': True}
    except Exception as e:
        logger.error("[mailer] Brand alert failed: %s", e)
        return {'ok': False, 'error': str(e)}
