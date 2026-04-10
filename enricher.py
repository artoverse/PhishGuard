import requests
from bs4 import BeautifulSoup
import whois
import ssl
import socket
import time
from datetime import datetime, timezone
from flask import current_app


# ─── WHOIS ─────────────────────────────────────────────────────────────────────

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        age_days = None
        if creation and isinstance(creation, datetime):
            # WHOIS datetimes may be timezone-aware (UTC) or naive.
            # Normalise both sides to UTC-aware before subtracting.
            if creation.tzinfo is not None:
                now = datetime.now(timezone.utc)
            else:
                now = datetime.utcnow()
            age_days = (now - creation).days

        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]

        return {
            'registrar': w.registrar,
            'creation_date': creation.isoformat() if creation else None,
            'expiration_date': (
                expiration.isoformat()
                if isinstance(expiration, datetime)
                else str(expiration) if expiration else None
            ),
            'age_days': age_days
        }
    except Exception as e:
        return {'error': f'WHOIS failed: {str(e)}'}


# ─── Web Fetcher + Content Phishing Analysis ─────────────────────────────────

def _analyse_page_content(soup, resp, domain, original_domain):
    """
    Inspect already-fetched HTML for real phishing page signals.
    Returns a dict of bool indicators — no extra HTTP request needed.
    """
    indicators = {
        'has_password_form':       False,
        'has_external_form_action': False,
        'brand_in_page':           False,
        'redirect_to_external':    False,
        'has_login_form':          False,
    }
    try:
        # 1. Password input present → credential harvesting page
        password_inputs = soup.find_all('input', {'type': 'password'})
        indicators['has_password_form'] = len(password_inputs) > 0

        # 2. Any form whose action submits to a different domain
        forms = soup.find_all('form')
        for form in forms:
            action = (form.get('action') or '').strip()
            if action.startswith('http') and domain not in action:
                indicators['has_external_form_action'] = True
                break

        # 3. Login-related form (username + password fields together)
        user_inputs = soup.find_all('input', {'type': lambda t: t and t.lower() in ('text', 'email')})
        if user_inputs and password_inputs:
            indicators['has_login_form'] = True

        # 4. Target brand name appears in page title or visible headings
        brand = original_domain.split('.')[0].lower()   # e.g. 'paypal' from 'paypal.com'
        page_text = ''
        if soup.title and soup.title.string:
            page_text += soup.title.string.lower()
        for tag in soup.find_all(['h1', 'h2', 'h3']):
            page_text += ' ' + tag.get_text().lower()
        if len(brand) >= 4 and brand in page_text:
            indicators['brand_in_page'] = True

        # 5. Final URL is on a completely different domain (external redirect)
        final_host = resp.url.split('/')[2].lower().lstrip('www.')
        self_host  = domain.lower().lstrip('www.')
        if final_host and self_host not in final_host and final_host not in self_host:
            indicators['redirect_to_external'] = True

    except Exception:
        pass   # non-fatal — missing indicators default to False

    return indicators


def fetch_web_content(domain, original_domain=''):
    results = {}
    for proto in ['https', 'http']:
        try:
            resp = requests.get(
                f"{proto}://{domain}",
                timeout=8,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; PhishGuard/1.0)'},
                allow_redirects=True
            )
            soup = BeautifulSoup(resp.text, 'html.parser')
            title = None
            if soup.title and soup.title.string:
                title = soup.title.string.strip()[:200]

            # Analyse page content for phishing signals (uses HTML already in memory)
            content_signals = _analyse_page_content(soup, resp, domain, original_domain)

            results[proto] = {
                'status':    resp.status_code,
                'title':     title,
                'final_url': resp.url,
                **content_signals,   # merge all phishing content indicators
            }
        except Exception:
            results[proto] = {'error': 'unreachable'}
    return results


# ─── SSL ──────────────────────────────────────────────────────────────────────

def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Parse issuer tuple of tuples into readable string
                issuer_raw = cert.get('issuer', ())
                issuer_parts = {}
                for rdn in issuer_raw:
                    for key, val in rdn:
                        issuer_parts[key] = val
                org     = issuer_parts.get('organizationName', '')
                cn      = issuer_parts.get('commonName', '')
                country = issuer_parts.get('countryName', '')
                issuer_str = org or cn
                if country and issuer_str:
                    issuer_str = f"{issuer_str} ({country})"
                elif country:
                    issuer_str = country
                return {
                    'valid':   True,
                    'issuer':  issuer_str or str(issuer_raw),
                    'expires': cert.get('notAfter', '')
                }
    except Exception:
        return {'valid': False}


# ─── VirusTotal ───────────────────────────────────────────────────────────────

def check_virustotal(domain):
    """
    Query the VirusTotal API v3 for a domain's threat intelligence.
    Returns structured data including engine verdicts and community score.
    Falls back gracefully if no API key or quota is exceeded.
    """
    try:
        api_key = current_app.config.get('VT_API_KEY', '')
    except RuntimeError:
        # Called outside app context (shouldn't happen, but guard anyway)
        api_key = ''

    if not api_key:
        return {
            'available': False,
            'reason': 'API key not configured',
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0,
            'engines_total': 0,
            'community_score': 0,
            'vt_link': f'https://www.virustotal.com/gui/domain/{domain}'
        }

    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': api_key, 'Accept': 'application/json'}

    try:
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 401:
            return {'available': False, 'reason': 'Invalid API key', 'malicious': 0,
                    'suspicious': 0, 'harmless': 0, 'undetected': 0,
                    'engines_total': 0, 'community_score': 0,
                    'vt_link': f'https://www.virustotal.com/gui/domain/{domain}'}

        if resp.status_code == 429:
            return {'available': False, 'reason': 'VT quota exceeded', 'malicious': 0,
                    'suspicious': 0, 'harmless': 0, 'undetected': 0,
                    'engines_total': 0, 'community_score': 0,
                    'vt_link': f'https://www.virustotal.com/gui/domain/{domain}'}

        if resp.status_code != 200:
            return {'available': False, 'reason': f'HTTP {resp.status_code}', 'malicious': 0,
                    'suspicious': 0, 'harmless': 0, 'undetected': 0,
                    'engines_total': 0, 'community_score': 0,
                    'vt_link': f'https://www.virustotal.com/gui/domain/{domain}'}

        data = resp.json()
        stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        malicious   = stats.get('malicious', 0)
        suspicious  = stats.get('suspicious', 0)
        harmless    = stats.get('harmless', 0)
        undetected  = stats.get('undetected', 0)
        engines_total = malicious + suspicious + harmless + undetected

        # Community reputation score (positive = good, negative = bad)
        community_score = data.get('data', {}).get('attributes', {}).get('reputation', 0)

        # Top engines that flagged it as malicious
        all_results = data.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
        flagging_engines = [
            engine for engine, result in all_results.items()
            if result.get('category') in ('malicious', 'suspicious')
        ][:5]  # Top 5 only

        return {
            'available': True,
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'undetected': undetected,
            'engines_total': engines_total,
            'community_score': community_score,
            'flagging_engines': flagging_engines,
            'vt_link': f'https://www.virustotal.com/gui/domain/{domain}'
        }

    except requests.Timeout:
        return {'available': False, 'reason': 'VT request timed out', 'malicious': 0,
                'suspicious': 0, 'harmless': 0, 'undetected': 0,
                'engines_total': 0, 'community_score': 0,
                'vt_link': f'https://www.virustotal.com/gui/domain/{domain}'}
    except Exception as e:
        return {'available': False, 'reason': str(e), 'malicious': 0,
                'suspicious': 0, 'harmless': 0, 'undetected': 0,
                'engines_total': 0, 'community_score': 0,
                'vt_link': f'https://www.virustotal.com/gui/domain/{domain}'}


# ─── Main Enricher ────────────────────────────────────────────────────────────

def enrich_domain(domain_data, original_domain):
    domain = domain_data['domain']
    enriched = {
        'whois':       get_whois_info(domain),
        'web':         fetch_web_content(domain, original_domain),   # pass brand for content analysis
        'ssl':         check_ssl(domain),
        'virustotal':  check_virustotal(domain),
        'original_domain': original_domain,
    }
    result = dict(domain_data)
    result.update(enriched)
    return result