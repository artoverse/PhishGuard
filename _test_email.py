"""
_test_email.py — Quick SMTP connectivity test
Run from the project root: python _test_email.py <recipient@email.com>

Reads configuration from .env automatically.
"""
import os, sys
from dotenv import load_dotenv

load_dotenv()  # reads .env from current directory

from mailer import send_test_email

smtp_cfg = {
    'server':     os.environ.get('MAIL_SERVER', ''),
    'port':       int(os.environ.get('MAIL_PORT', 587)),
    'username':   os.environ.get('MAIL_USERNAME', ''),
    'password':   os.environ.get('MAIL_PASSWORD', ''),
    'from_email': os.environ.get('MAIL_FROM', os.environ.get('ALERT_FROM_EMAIL', '')),
    'use_tls':    os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true',
}

recipient = sys.argv[1] if len(sys.argv) > 1 else smtp_cfg['username']

print(f'MAIL_SERVER   = {smtp_cfg["server"]}')
print(f'MAIL_USERNAME = {smtp_cfg["username"]}')
print(f'MAIL_PASSWORD = {"*" * len(smtp_cfg["password"])} ({len(smtp_cfg["password"])} chars)')
print(f'Sending test email to: {recipient}')
print()

result = send_test_email(recipient, smtp_cfg)
if result['ok']:
    print(f'✅ Email sent to {recipient} — check inbox!')
else:
    print(f'❌ SMTP Error: {result["error"]}')
