"""
PhishGuard — Hybrid Risk Scorer (XGBoost + Evidence-Weighted Rules)
====================================================================
Combines a trained XGBoost classifier (UCI Phishing Dataset) with a
deterministic evidence-weighted rule scorer for maximum accuracy.

Fusion strategy:
  • XGBoost handles structural, WHOIS, SSL, and DNS features (trained on
    11k real labelled samples — no synthetic data).
  • Rule scorer handles VirusTotal intelligence, visual similarity (Levenshtein),
    and live page-content signals — things no pre-trained model can know.
  • Final score = 0.55 × ML score + 0.45 × rule score
  • VirusTotal hard override is ALWAYS applied regardless of ML output.

Scoring layout (max 100 pts):
  ┌───────────────────────────────────┬──────┐
  │ Signal Group                      │  Max │
  ├───────────────────────────────────┼──────┤
  │ XGBoost ML (UCI features)         │  60  │
  │ VirusTotal Intelligence           │  50  │
  │ Domain Age / WHOIS                │  25  │
  │ Visual Similarity (Levenshtein)   │  20  │
  │ Domain Structure (keywords/TLD)   │  15  │
  │ Page Content Analysis             │  20  │
  │ SSL Certificate                   │   5  │
  └───────────────────────────────────┴──────┘
  Raw total > 100 is clamped to 100.
"""

import math
import os
from Levenshtein import distance as lev_distance

try:
    from ml_scorer import ml_score, is_model_available
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False
    def ml_score(*_, **__):
        return {'available': False, 'probability': 0.5, 'ml_score': 0, 'features': {}, 'reason': 'ml_scorer not found'}
    def is_model_available():
        return False


# ─── Helpers ──────────────────────────────────────────────────────────────────

def entropy(s):
    freq = {c: s.lower().count(c) for c in set(s.lower())}
    return -sum((count / len(s)) * math.log2(count / len(s))
                for count in freq.values()) if s else 0


def get_sld(domain: str) -> str:
    """
    Extract the second-level domain label only.
    'paypal-secure-login.com' → 'paypal-secure-login'
    'login.paypal.com'        → 'paypal'
    """
    parts = domain.lower().split('.')
    parts = [p.split(':')[0] for p in parts]   # strip any :port
    return parts[-2] if len(parts) >= 2 else parts[0]


def _has_digit_substitution(domain: str) -> bool:
    """Detect classic phishing digit tricks: 0→o, 1→l, 3→e, 4→a, 5→s, etc."""
    subs = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g', '8': 'b'}
    sld = get_sld(domain)
    normalized = sld
    for digit, letter in subs.items():
        normalized = normalized.replace(digit, letter)
    return normalized != sld  # if normalization changed anything, substitution exists


# ─── Signal Group Scorers ─────────────────────────────────────────────────────

def _score_virustotal(vt: dict) -> tuple[int, list[str]]:
    """
    VirusTotal intelligence — strongest external authority signal.
    Max 50 points.
    """
    pts = 0
    signals = []

    if not vt.get('available', False):
        return pts, signals   # VT not available → no contribution either way

    malicious  = vt.get('malicious', 0)
    suspicious = vt.get('suspicious', 0)
    community  = vt.get('community_score', 0)

    if malicious >= 10:
        pts = 50
        signals.append(f'VT: {malicious} engines flagged malicious')
    elif malicious >= 5:
        pts = 45
        signals.append(f'VT: {malicious} engines flagged malicious')
    elif malicious >= 3:
        pts = 40
        signals.append(f'VT: {malicious} engines flagged malicious')
    elif malicious >= 1:
        pts = 30
        signals.append(f'VT: {malicious} engine(s) flagged malicious')
    elif suspicious >= 5:
        pts = 25
        signals.append(f'VT: {suspicious} engines flagged suspicious')
    elif suspicious >= 2:
        pts = 18
        signals.append(f'VT: {suspicious} engines flagged suspicious')
    elif suspicious >= 1:
        pts = 10
        signals.append('VT: 1 engine flagged suspicious')

    if community < -5:
        pts = min(pts + 8, 50)
        signals.append(f'VT community score: {community}')

    return min(pts, 50), signals


def _score_domain_age(whois: dict) -> tuple[int, list[str]]:
    """
    Domain age and WHOIS availability.
    Max 25 points.
    """
    pts = 0
    signals = []
    has_error = 'error' in str(whois)
    age = whois.get('age_days')

    if has_error or age is None:
        # WHOIS blocked / failed → suspicious on its own
        pts = 12
        signals.append('WHOIS blocked or unavailable')
        return pts, signals

    if age < 7:
        pts = 25
        signals.append(f'domain only {age}d old (very new)')
    elif age < 30:
        pts = 20
        signals.append(f'domain {age}d old (recently registered)')
    elif age < 90:
        pts = 13
        signals.append(f'domain {age}d old')
    elif age < 180:
        pts = 7
        signals.append(f'domain {age}d old')
    elif age < 365:
        pts = 3
    # age >= 365 → established domain, no points

    return min(pts, 25), signals


def _score_visual_similarity(domain: str, original: str) -> tuple[int, list[str]]:
    """
    How visually close is this domain to the target brand at SLD level.
    Max 20 points.
    """
    pts = 0
    signals = []
    dist = lev_distance(get_sld(domain), get_sld(original))

    if dist == 0:
        pts = 20
        signals.append('exact SLD match (IDN or clone)')
    elif dist == 1:
        pts = 18
        signals.append(f'1-char SLD difference (very close lookalike)')
    elif dist == 2:
        pts = 14
        signals.append(f'2-char SLD difference (close lookalike)')
    elif dist == 3:
        pts = 10
        signals.append(f'3-char SLD difference (lookalike)')
    elif dist == 4:
        pts = 6
        signals.append(f'4-char SLD difference')
    elif dist <= 6:
        pts = 3

    return min(pts, 20), signals


def _score_domain_structure(domain: str) -> tuple[int, list[str]]:
    """
    Domain structural indicators: keywords, TLD, digit substitution, hyphens, length.
    Max 15 points.
    """
    pts = 0
    signals = []

    PHISHING_KEYWORDS = {
        'login', 'secure', 'account', 'verify', 'bank', 'paypal', 'update',
        'signin', 'password', 'wallet', 'crypto', 'support', 'service',
        'alert', 'confirm', 'billing', 'auth', 'access', 'recovery',
        'help', 'official', 'ebay', 'amazon', 'apple', 'microsoft',
        'google', 'netflix', 'instagram', 'facebook', 'whatsapp',
    }

    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'pw', 'ru', 'cn',
        'cc', 'ws', 'biz', 'info', 'online', 'click', 'link', 'live',
        'shop', 'site', 'icu', 'fun', 'buzz', 'work', 'loan', 'win',
    }

    sld = get_sld(domain)
    tld = domain.split('.')[-1].split(':')[0].lower()

    # Phishing keyword in SLD
    matched_kw = [k for k in PHISHING_KEYWORDS if k in sld]
    if matched_kw:
        pts += 10
        signals.append(f'phishing keyword: {matched_kw[0]}')

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        pts += 6
        signals.append(f'suspicious TLD (.{tld})')

    # Digit substitution tricks (paypa1, g00gle, etc.)
    if _has_digit_substitution(domain):
        pts += 8
        signals.append('digit substitution detected (e.g. 0→o, 1→l)')

    # Multiple hyphens (paypal-secure-login)
    hyphen_count = sld.count('-')
    if hyphen_count >= 2:
        pts += 5
        signals.append(f'{hyphen_count} hyphens in domain')
    elif hyphen_count == 1:
        pts += 2

    # Unusually long domain
    if len(domain) > 40:
        pts += 4
        signals.append(f'long domain ({len(domain)} chars)')
    elif len(domain) > 30:
        pts += 2

    return min(pts, 15), signals


def _score_page_content(web: dict) -> tuple[int, list[str]]:
    """
    Page content phishing signals extracted during enrichment.
    Max 20 points.
    """
    pts = 0
    signals = []

    # Use HTTPS data preferentially, fall back to HTTP
    page = web.get('https', {}) if not web.get('https', {}).get('error') else web.get('http', {})

    if not page or page.get('error'):
        return 0, []   # page unreachable — no content signal

    if page.get('has_password_form'):
        pts += 12
        signals.append('page has password/credential form')

    if page.get('has_external_form_action'):
        pts += 10
        signals.append('form submits credentials to external domain')

    if page.get('brand_in_page'):
        pts += 8
        signals.append('target brand name found in page content')

    if page.get('has_login_form'):
        pts += 5
        signals.append('login form detected (username + password)')

    if page.get('redirect_to_external'):
        pts += 5
        signals.append('page redirects to external domain')

    return min(pts, 20), signals


def _score_ssl(ssl: dict) -> tuple[int, list[str]]:
    """
    SSL certificate presence.
    Max 5 points — weak signal alone (LetsEncrypt is free), but contributes
    as a tie-breaker in combination with other signals.
    """
    if not ssl.get('valid', False):
        return 5, ['no valid SSL certificate']
    return 0, []


# ─── Main Analyser ────────────────────────────────────────────────────────────

def analyze_risk(domain_data: dict, original: str) -> dict:
    """
    Hybrid scorer: XGBoost ML + deterministic evidence rules.

    Fusion:
      • ML signal covers structural / WHOIS / SSL / DNS (trained on UCI dataset).
      • Rule signal covers VirusTotal, visual similarity, page content.
      • final_score = 0.55 × ml_raw + 0.45 × rule_raw  (clamped to 100)
      • VT hard override always applies: if VT confirms ≥3 engines → score ≥ 75.

    Returns a dict compatible with the existing app.py / DB schema.
    """
    domain = domain_data['domain']
    vt     = domain_data.get('virustotal', {})
    whois  = domain_data.get('whois', {})
    ssl    = domain_data.get('ssl', {})
    web    = domain_data.get('web', {})

    # ── Rule-based signal groups ──────────────────────────────────────────────
    vt_pts,       vt_sigs       = _score_virustotal(vt)
    age_pts,      age_sigs      = _score_domain_age(whois)
    sim_pts,      sim_sigs      = _score_visual_similarity(domain, original)
    struct_pts,   struct_sigs   = _score_domain_structure(domain)
    content_pts,  content_sigs  = _score_page_content(web)
    ssl_pts,      ssl_sigs      = _score_ssl(ssl)

    rule_raw = vt_pts + age_pts + sim_pts + struct_pts + content_pts + ssl_pts

    # ── XGBoost ML signal ─────────────────────────────────────────────────────
    ml_result = ml_score(domain_data, original)
    ml_raw    = ml_result.get('ml_score', 0)    # 0–60 range
    ml_avail  = ml_result.get('available', False)
    ml_prob   = ml_result.get('probability', 0.5)

    # ── Hybrid fusion ─────────────────────────────────────────────────────────
    if ml_avail:
        # Weighted combination: ML covers structure/WHOIS/SSL/DNS;
        # rules cover VT + content + visual similarity
        fused = 0.55 * ml_raw + 0.45 * rule_raw
    else:
        # Fallback: pure rule-based scoring (original behaviour)
        fused = float(rule_raw)

    score = min(int(round(fused)), 100)

    # ── VT confirmed = hard override regardless of ML output ──────────────────
    vt_confirmed = vt.get('available', False) and vt.get('malicious', 0) >= 3
    if vt_confirmed:
        score = max(score, 75)   # ensure classification is at least Malicious

    # ── Risk classification ─────────────────────────────────────────────────────
    # Fixed 3-tier model:
    #   🟢 Safe       score <  28  → registered lookalike, no active threat signals.
    #                               Monitor passively.
    #   🟠 Suspicious score 28–74  → phishing indicators present, not yet confirmed.
    #                               Investigate manually.
    #   🔴 Malicious  score >= 75  → active phishing or confirmed by threat intel.
    #   or VT confirmed              Block immediately.
    vt_missing = not vt.get('available', False)

    if score >= 75 or vt_confirmed:
        status     = 'Malicious'
        emoji      = '🔴'
        action     = 'Block immediately'
        confidence = 0.95 if vt_confirmed else (round(ml_prob, 2) if ml_avail else 0.88)
    elif score >= 28:
        status     = 'Suspicious'
        emoji      = '🟠'
        action     = 'Investigate manually'
        confidence = round(ml_prob, 2) if ml_avail else 0.80
    else:
        status     = 'Safe'
        emoji      = '🟢'
        action     = 'Monitor passively'
        confidence = round(1 - ml_prob, 2) if ml_avail else 0.92

    # ── Proximity override ────────────────────────────────────────────────────
    # New phishing domains at dist==1 ALREADY cross the 28-pt Suspicious
    # threshold naturally (age_pts 15-25 + sim_pts 18 + ssl_pts 5 > 28).
    # Old established domains (goole.com: 9648 days, googlee.com: 9499 days)
    # should stay Safe — they are parked, not actively attacking anyone.
    #
    # The only narrow case warranting an override: dist==1 domain where WHOIS
    # age is completely unavailable (None) — hidden registration hiding age is
    # itself a risk signal when combined with a near-identical name.
    lev_dist = lev_distance(get_sld(domain), get_sld(original))
    age_days_val = whois.get('age_days')
    proximity_override = (
        vt_missing and status == 'Safe' and
        lev_dist == 1 and
        age_days_val is None       # WHOIS age unknown → treat opaque domain as suspicious
    )
    if proximity_override:
        status     = 'Suspicious'
        emoji      = '🟠'
        action     = 'Investigate manually'
        confidence = round(ml_prob, 2) if ml_avail else 0.65


    # ── Build explanation ─────────────────────────────────────────────────────
    all_signals = vt_sigs + age_sigs + sim_sigs + struct_sigs + content_sigs + ssl_sigs
    if ml_avail:
        score_breakdown = (
            f"ML:{ml_raw}(p={ml_prob:.2f}) VT:{vt_pts} Age:{age_pts} "
            f"Sim:{sim_pts} Struct:{struct_pts} Content:{content_pts} SSL:{ssl_pts}"
        )
        ml_note = f'GBM P(phish)={ml_prob:.1%}'
        all_signals = [ml_note] + all_signals
    else:
        score_breakdown = (
            f"VT:{vt_pts} Age:{age_pts} Sim:{sim_pts} "
            f"Struct:{struct_pts} Content:{content_pts} SSL:{ssl_pts} [rule-only]"
        )

    explanation = (
        f"Score {score}/100 [{score_breakdown}] — "
        + (', '.join(all_signals) if all_signals else 'no strong signals detected')
    )
    if proximity_override:
        explanation += (
            f' ⚠️ Proximity flag: {lev_dist}-char lookalike — '
            'verify manually (no VT data available)'
        )

    # ── Features dict (kept for DB/modal compatibility) ───────────────────────
    age_raw = whois.get('age_days')
    features = {
        'levenshtein':       lev_distance(get_sld(domain), get_sld(original)),
        'entropy':           entropy(domain),
        'age_days':          age_raw,
        'whois_failed':      int('error' in str(whois) or age_raw is None),
        'suspicious_tld':    int(domain.split('.')[-1].split(':')[0].lower() in {
                                 'tk','ml','ga','cf','gq','xyz','top','pw','ru','cn',
                                 'cc','ws','biz','info','online','click','link','live',
                                 'shop','site','icu','fun',
                             }),
        'keyword_match':     int(any(k in get_sld(domain) for k in [
                                 'login','secure','account','verify','bank','update',
                                 'signin','password','wallet','crypto','support','billing',
                             ])),
        'ssl_valid':         int(ssl.get('valid', False)),
        'dns_a_count':       len(domain_data.get('dns_a', []))
                             if isinstance(domain_data.get('dns_a'), list) else 0,
        'web_reachable':     int(bool(web.get('https', {}).get('status') == 200 or
                                      web.get('http',  {}).get('status') == 200)),
        'vt_malicious':      vt.get('malicious', 0),
        'vt_suspicious':     vt.get('suspicious', 0),
        'vt_available':      vt.get('available', False),
        'vt_community_neg':  int(vt.get('community_score', 0) < -5),
        # Content signals
        'has_password_form':        web.get('https', {}).get('has_password_form', False),
        'has_external_form_action': web.get('https', {}).get('has_external_form_action', False),
        'brand_in_page':            web.get('https', {}).get('brand_in_page', False),
        'has_login_form':           web.get('https', {}).get('has_login_form', False),
        # Score breakdown
        'score_vt':      vt_pts,
        'score_age':     age_pts,
        'score_sim':     sim_pts,
        'score_struct':  struct_pts,
        'score_content': content_pts,
        'score_ssl':     ssl_pts,
        # ML signal
        'ml_probability':  ml_prob if ml_avail else None,
        'ml_score':        ml_raw  if ml_avail else None,
        'ml_available':    ml_avail,
        'ml_features':     ml_result.get('features', {}),
    }

    return {
        'risk_score':    score,
        'risk_status':   status,
        'risk_emoji':    emoji,
        'risk_action':   action,        # "Monitor passively / Investigate manually / Block immediately"
        'features':      features,
        'confidence':    confidence,
        'explanation':   explanation,
        'vt_confirmed':  vt_confirmed,
        'ml_available':  ml_avail,
        'ml_probability': ml_prob if ml_avail else None,
    }