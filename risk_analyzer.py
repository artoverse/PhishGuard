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
    Domain age + WHOIS registration quality signals.
    Max 40 points (raised from 25 to accommodate new WHOIS signals).

    Signals scored:
      • Domain creation age              (0–25 pts)
      • Days until expiry                (0–12 pts) — 1-yr throwaway registrations
      • WHOIS registrant privacy service (0–5  pts) — hidden owner
      • Registrant country risk          (0–4  pts) — high-abuse ccTLD
    """
    pts = 0
    signals = []
    has_error = 'error' in str(whois)
    age = whois.get('age_days')

    if has_error or age is None:
        pts = 12
        signals.append('WHOIS blocked or unavailable')
        return pts, signals

    # ── Age of domain since creation ──────────────────────────────────────────
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
    # age >= 365 → established domain, no age points

    # ── Days to expiry — short registration = throwaway domain ───────────────
    dte = whois.get('days_to_expiry')
    if dte is not None:
        if dte < 0:
            pts += 10
            signals.append('domain already expired (zombie/takeover risk)')
        elif dte < 60:
            pts += 12
            signals.append(f'expires in {dte}d (throwaway registration)')
        elif dte < 180:
            pts += 8
            signals.append(f'expires in {dte}d (short registration)')
        elif dte < 365:
            pts += 5
            signals.append(f'expires in {dte}d (1-year registration)')
    else:
        # Expiry date hidden/unavailable alongside known age → extra suspicion
        pts += 3
        signals.append('expiry date hidden from WHOIS')

    # ── Registrant privacy service — real owner concealed ────────────────────
    if whois.get('registrant_is_private'):
        pts += 5
        signals.append('WHOIS registrant hidden behind privacy service')

    # ── Registrant country risk ───────────────────────────────────────────────
    HIGH_RISK_COUNTRIES = {
        'RU', 'CN', 'NG', 'UA', 'KZ', 'TR', 'KP', 'IR', 'VN', 'ID',
        'BR', 'PK', 'BD', 'GH', 'EG', 'MA',
    }
    country = whois.get('registrant_country', '') or ''
    if country.upper() in HIGH_RISK_COUNTRIES:
        pts += 4
        signals.append(f'registrant country: {country} (high-abuse region)')

    return min(pts, 40), signals


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
        pts = 22   # boosted: 1-edit lookalikes are the highest-risk visual class
        signals.append('1-char SLD difference (very close lookalike)')
    elif dist == 2:
        pts = 16   # boosted slightly
        signals.append('2-char SLD difference (close lookalike)')
    elif dist == 3:
        pts = 10
        signals.append('3-char SLD difference (lookalike)')
    elif dist == 4:
        pts = 6
        signals.append('4-char SLD difference')
    elif dist <= 6:
        pts = 3

    return min(pts, 22), signals


def _score_domain_structure(domain: str) -> tuple[int, list[str]]:
    """
    Domain structural indicators: keywords, TLD, digit substitution, hyphens, length.
    Max 15 points.
    """
    pts = 0
    signals = []

    PHISHING_KEYWORDS = {
        # Actions / security terms
        'login', 'secure', 'account', 'verify', 'update', 'signin', 'signout',
        'password', 'auth', 'access', 'recovery', 'confirm', 'billing', 'alert',
        'support', 'service', 'help', 'official', 'wallet', 'crypto', 'bank',
        # Financial brands
        'paypal', 'ebay', 'amazon', 'chase', 'wellsfargo', 'barclays', 'hsbc',
        'citibank', 'visa', 'mastercard', 'amex', 'stripe', 'coinbase', 'binance',
        # Tech / social brands
        'google', 'gmail', 'youtube', 'microsoft', 'outlook', 'office365',
        'apple', 'icloud', 'netflix', 'instagram', 'facebook', 'whatsapp',
        'twitter', 'tiktok', 'snapchat', 'linkedin', 'discord', 'twitch',
        'dropbox', 'github', 'gitlab', 'spotify', 'steam', 'roblox',
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


def _active_page(web: dict) -> dict:
    """Return the best available page data — HTTPS preferred, fall back to HTTP."""
    https = web.get('https', {})
    return https if not https.get('error') else web.get('http', {})


def _score_page_content(web: dict) -> tuple[int, list[str]]:
    """
    Page content phishing signals extracted during enrichment.
    Max 20 points.
    """
    pts = 0
    signals = []

    # Use HTTPS data preferentially, fall back to HTTP
    page = _active_page(web)

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

    rule_raw_base = vt_pts + age_pts + sim_pts + struct_pts + content_pts + ssl_pts

    # ── Multi-signal combination bonus ────────────────────────────────────────
    # Stacked independent signals (from different dimensions) are much stronger
    # evidence of intent than any single signal alone.
    # Each dimension fired beyond 2 adds +8 pts to rule_raw.
    _dte = whois.get('days_to_expiry')
    _combo_signals = sum([
        int(sim_pts    >= 18),                                         # close lookalike
        int(ssl_pts    >  0),                                          # missing SSL
        int(age_pts    >= 5 or (_dte is not None and _dte < 365)),     # short/hidden registration
        int(struct_pts >= 8),                                          # phishing keyword/pattern
        int(content_pts > 0),                                          # active phishing content
    ])
    _combo_bonus = (_combo_signals - 2) * 8 if _combo_signals >= 3 else 0
    rule_raw = min(rule_raw_base + _combo_bonus, 100)

    # ── XGBoost ML signal ─────────────────────────────────────────────────────
    ml_result = ml_score(domain_data, original)
    ml_raw    = ml_result.get('ml_score', 0)    # 0–60 range
    ml_avail  = ml_result.get('available', False)
    ml_prob   = ml_result.get('probability', 0.5)

    # ── Hybrid fusion ─────────────────────────────────────────────────────────
    if ml_avail:
        fused = 0.55 * ml_raw + 0.45 * rule_raw
    else:
        fused = float(rule_raw)

    score = min(int(round(fused)), 100)

    # ── VT confirmed = hard override regardless of ML output ──────────────────
    vt_confirmed = vt.get('available', False) and vt.get('malicious', 0) >= 3
    if vt_confirmed:
        score = max(score, 75)

    # ── Risk classification ───────────────────────────────────────────────────
    # When VT is available:   Safe<28,  Suspicious 28–74, Malicious≥75
    # When VT is unavailable: Safe<22,  Suspicious 22–51, Malicious≥52
    #
    # Without VT the math max score is ~71. Thresholds scale proportionally.
    # Malicious at 52 requires stacking ≥3 signals simultaneously:
    #   e.g. fresh domain (<7d) + dist=1 + no SSL + brand/password in page
    # Single-signal domains (visual similarity only) stay Suspicious at 22–40.
    vt_missing = not vt.get('available', False)

    if vt_missing:
        t_malicious  = 52   # needs multiple strong signals stacked
        t_suspicious = 22   # catches any dist=1 lookalike with secondary signal
    else:
        t_malicious  = 75
        t_suspicious = 28

    if score >= t_malicious or vt_confirmed:
        status     = 'Malicious'
        emoji      = '🔴'
        action     = 'Block immediately'
        confidence = 0.95 if vt_confirmed else (round(ml_prob, 2) if ml_avail else 0.88)
    elif score >= t_suspicious:
        status     = 'Suspicious'
        emoji      = '🟠'
        action     = 'Investigate manually'
        confidence = round(ml_prob, 2) if ml_avail else 0.80
    else:
        status     = 'Safe'
        emoji      = '🟢'
        action     = 'Monitor passively'
        confidence = round(1 - ml_prob, 2) if ml_avail else 0.92

    # ── Rule-based score floors (VT-blind protection) ─────────────────────────
    # The ML model was trained on generic URL features (UCI dataset). It cannot
    # detect brand-similarity intent — it classifies old established domains as
    # "safe" because they have legitimate-looking signals (old, valid SSL, long
    # expiry). When VT is unavailable, rule evidence must act as a safety net.
    #
    # Floor 1 — Suspicious (dist=1 + secondary evidence):
    #   If a close lookalike has ≥8 pts from non-visual signals (keyword,
    #   structure, registration, SSL), it cannot be rated Safe by ML alone.
    #
    # Floor 2 — Malicious (3+ independent dimensions + rule crosses threshold):
    #   When separate evidence from 3+ dimensions (visual, registration/expiry,
    #   SSL, structure, content) fires simultaneously AND rule_raw already
    #   clears the Malicious threshold, enforce that classification regardless
    #   of what ML says about the domain's structural legitimacy.
    if vt_missing and ml_avail:
        _rule_beyond_visual = rule_raw_base - sim_pts   # pts from signals other than sim
        # Floor 1 — at least Suspicious
        if (sim_pts >= 22 and _rule_beyond_visual >= 8 and status == 'Safe'):
            score  = t_suspicious
            status = 'Suspicious'
            emoji  = '🟠'
            action = 'Investigate manually'
            confidence = round(ml_prob, 2)
        # Floor 2 — at least Malicious
        if (_combo_signals >= 3 and rule_raw >= t_malicious and score < t_malicious):
            score  = t_malicious
            status = 'Malicious'
            emoji  = '🔴'
            action = 'Block immediately'
            confidence = round(ml_prob, 2)


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
        # Content signals — use same HTTPS→HTTP fallback as _score_page_content
        'has_password_form':        _active_page(web).get('has_password_form',        False),
        'has_external_form_action': _active_page(web).get('has_external_form_action', False),
        'brand_in_page':            _active_page(web).get('brand_in_page',            False),
        'has_login_form':           _active_page(web).get('has_login_form',           False),
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