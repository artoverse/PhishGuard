import os, sys
sys.path.insert(0, '/Users/del/hopeful/S8/PS2/phishguard')
os.chdir('/Users/del/hopeful/S8/PS2/phishguard')

from dotenv import load_dotenv
load_dotenv('/Users/del/hopeful/S8/PS2/phishguard/.env')

from mailer import send_test_email

smtp_cfg = {
    'server':     os.environ.get('MAIL_SERVER', ''),
    'port':       int(os.environ.get('MAIL_PORT', 587)),
    'username':   os.environ.get('MAIL_USERNAME', ''),
    'password':   os.environ.get('MAIL_PASSWORD', ''),
    'from_email': os.environ.get('ALERT_FROM_EMAIL', ''),
    'use_tls':    True,
}

print(f'MAIL_SERVER   = {smtp_cfg["server"]}')
print(f'MAIL_USERNAME = {smtp_cfg["username"]}')
print(f'MAIL_PASSWORD = {"*" * len(smtp_cfg["password"])} ({len(smtp_cfg["password"])} chars)')
print()

result = send_test_email(smtp_cfg['username'], smtp_cfg)
if result['ok']:
    print(f'✅ Email sent to {smtp_cfg["username"]} — check inbox!')
else:
    print(f'❌ SMTP Error: {result["error"]}')
