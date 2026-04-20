"""
PhishGuard — ml_scorer.py
==========================
Loads the trained Gradient Boosting model (phishguard_xgb.pkl) and computes
a phishing probability score from live enriched domain data.

Algorithm: scikit-learn HistGradientBoostingClassifier
  - Same gradient boosting family as XGBoost
  - Native NaN support (missing WHOIS handled automatically)
  - No native library dependency (works on any platform)
  - Trained on 58,645 real-labelled URLs (Vrbancic et al., 2020)

Feature mapping (dataset column → PhishGuard enricher → what we compute):
  domain_in_ip           → is_ip_domain       → raw IP as hostname?
  domain_length          → domain_length       → len(domain)
  qty_hyphen_domain      → hyphen_count        → hyphens in domain
  qty_at_url             → has_at_symbol       → '@' in URL
  qty_dot_domain         → dot_count           → dots (subdomain depth)
  tls_ssl_certificate    → ssl_valid           → valid SSL cert?
  time_domain_activation → age_days            → days since registration
  time_domain_expiration → days_to_expiry      → days until expiry
  url_shortened          → is_shortener        → bit.ly / tinyurl?
  qty_ip_resolved        → dns_a_count         → number of A records
  qty_nameservers        → dns_ns_count        → number of NS records
  qty_mx_servers         → dns_mx_count        → number of MX records
  qty_redirects          → redirect_count      → number of HTTP redirects
"""

import os
import pickle
import re
import math
import numpy as np
from datetime import datetime

_MODEL_CACHE = None
_MODEL_PATH  = os.path.join(os.path.dirname(__file__), 'phishguard_xgb.pkl')

# Known URL shortener domains
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'cli.gs',
    'pi.pe', 'cutt.ly', 'rb.gy', 'shorturl.at',
}


# ─── Model I/O ────────────────────────────────────────────────────────────────

def load_model(path=None):
    """Load phishguard_xgb.pkl once and cache it. Returns (model, feature_names)."""
    global _MODEL_CACHE
    if _MODEL_CACHE is not None:
        return _MODEL_CACHE
    p = path or _MODEL_PATH
    if not os.path.exists(p):
        return None, None
    with open(p, 'rb') as f:
        payload = pickle.load(f)
    model         = payload['model']
    feature_names = payload['features']
    _MODEL_CACHE  = (model, feature_names)
    print(f"✅ [ml_scorer] Model loaded from {p} ({len(feature_names)} features)")
    return _MODEL_CACHE


def is_model_available():
    """True if the model file exists on disk."""
    return os.path.exists(_MODEL_PATH)


# ─── Feature Extractors ───────────────────────────────────────────────────────

def _is_ip(domain: str) -> int:
    """1 if domain is a raw IPv4/v6 address, else 0."""
    ip4 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    ip6 = re.compile(r'^[0-9a-fA-F:]+$')
    return int(bool(ip4.match(domain) or ((':' in domain) and ip6.match(domain))))


def _days_to_expiry(whois: dict) -> float:
    """Days remaining until domain expiry. -1 if unknown."""
    # Use pre-computed value stored by enricher (fast path)
    dte = whois.get('days_to_expiry')
    if dte is not None:
        return max(float(dte), 0)
    # Fall back: compute from expiration_date ISO string (legacy data)
    try:
        exp_str = whois.get('expiration_date')
        if not exp_str:
            return -1
        exp = datetime.fromisoformat(str(exp_str)[:19])
        return max((exp - datetime.utcnow()).days, 0)
    except Exception:
        return -1



def _age_days(whois: dict) -> float:
    """Days since domain registration. -1 if unknown (matches dataset missing value)."""
    age = whois.get('age_days')
    return age if age is not None else -1


def _redirect_count(web: dict) -> int:
    """Number of HTTP redirects observed. 0 if no web data."""
    # We don't track exact redirect count, but we do know if a redirect happened
    # (redirect_to_external flag). Approximate: 0 = no redirect, 1 = redirect.
    https_web = web.get('https', {})
    http_web  = web.get('http',  {})
    page = https_web if not https_web.get('error') else http_web
    return 1 if page.get('redirect_to_external') else 0


# ─── Main Feature Vector Builder ──────────────────────────────────────────────

def build_feature_vector(domain_data: dict, original: str) -> dict:
    """
    Convert a PhishGuard enriched domain_data dict into the model's feature dict.
    NaN values are allowed — HistGradientBoostingClassifier handles them natively.

    Returns a flat dict keyed by internal feature name.
    """
    domain = domain_data.get('domain', '')
    whois  = domain_data.get('whois', {})
    ssl    = domain_data.get('ssl',   {})
    web    = domain_data.get('web',   {})

    dns_a  = domain_data.get('dns_a', [])
    dns_ns = domain_data.get('dns_ns', [])
    dns_mx = domain_data.get('dns_mx', [])

    return {
        'is_ip_domain':   _is_ip(domain),
        'domain_length':  len(domain),
        'hyphen_count':   domain.split('.')[0].count('-'),
        'has_at_symbol':  int('@' in domain),
        'dot_count':      domain.count('.'),
        'ssl_valid':      int(ssl.get('valid', False)),
        'age_days':       _age_days(whois),
        'days_to_expiry': _days_to_expiry(whois),
        'is_shortener':   int(domain.lower() in SHORTENERS),
        'dns_a_count':    len(dns_a)  if isinstance(dns_a,  list) else 0,
        'dns_ns_count':   len(dns_ns) if isinstance(dns_ns, list) else 0,
        'dns_mx_count':   len(dns_mx) if isinstance(dns_mx, list) else 0,
        'redirect_count': _redirect_count(web),
    }


# ─── Scoring Entry Point ──────────────────────────────────────────────────────

def ml_score(domain_data: dict, original: str) -> dict:
    """
    Run model prediction on one enriched domain.

    Returns:
        {
          'available':    bool,   # True if model file was found + loaded
          'probability':  float,  # phishing probability 0.0–1.0
          'ml_score':     int,    # 0–60 contribution to hybrid scorer
          'features':     dict,   # extracted feature values
          'reason':       str     # human-readable note
        }
    """
    model, feature_names = load_model()

    if model is None:
        return {
            'available': False,
            'probability': 0.5,
            'ml_score': 0,
            'features': {},
            'reason': 'Model not trained yet — run: python3 train_xgb.py'
        }

    fvec = build_feature_vector(domain_data, original)

    # Build DataFrame in the exact column order the model was trained on
    import pandas as pd
    X = pd.DataFrame([{f: fvec.get(f, np.nan) for f in feature_names}])

    try:
        prob = float(model.predict_proba(X)[0][1])   # P(phishing)
    except Exception as e:
        return {
            'available': True,
            'probability': 0.5,
            'ml_score': 0,
            'features': fvec,
            'reason': f'Prediction error: {e}'
        }

    # Map probability to 0–60 score contribution
    ml_pts = int(prob * 60)

    return {
        'available': True,
        'probability': round(prob, 4),
        'ml_score': ml_pts,
        'features': fvec,
        'reason': f'GradientBoosting P(phishing)={prob:.2%}'
    }
