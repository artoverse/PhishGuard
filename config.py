import os
from dotenv import load_dotenv

load_dotenv()  # for .env support (SMTP, keys, etc.)

# Absolute project root (this fixes the macOS SQLite error)
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'phishguard-dev-key-change-me-in-prod'
    
    # Absolute SQLite path → no more "unable to open database file"
    db_path = os.path.join(basedir, 'instance', 'phishguard.db')
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{db_path}'
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    # SQLite engine options:
    # - WAL journal mode: allows concurrent reads+writes without locking readers out
    # - busy_timeout: wait up to 10s before raising "database is locked" error
    SQLALCHEMY_ENGINE_OPTIONS = {
        'connect_args': {
            'timeout': 10,          # seconds to wait on a locked db
            'check_same_thread': False,
        },
        'pool_pre_ping': True,
    }
    
    # VirusTotal API key (get free key at virustotal.com)
    VT_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')

    # Optional: email alerts (add SMTP details to .env later)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    ALERT_FROM_EMAIL = os.environ.get('ALERT_FROM_EMAIL')