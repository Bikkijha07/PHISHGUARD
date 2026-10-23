"""
Feature Extractor Module
Extracts 30+ features from a URL for phishing detection
"""

import re
import math
import urllib.parse
from collections import Counter


# Known URL shorteners
URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'cli.gs', 'pic.gd', 'DwarfURL.com', 'yfrog.com', 'migre.me',
    'ff.im', 'tiny.cc', 'url4.eu', 'tr.im', 'twit.ac', 'su.pr',
    'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm',
    'post.ly', 'Just.as', 'bkite.com', 'snipr.com', 'fic.kr',
    'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me',
    'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 'lnkd.in', 'db.tt',
    'qr.ae', 'adf.ly', 'bitly.com', 'cur.lv', 'tinyurl.com',
    'ity.im', 'q.gs', 'po.st', 'bc.vc', 'twitthis.com', 'u.to',
    'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org'
}

# Suspicious TLDs associated with free domains / phishing
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'click', 'link',
    'xyz', 'men', 'loan', 'download', 'racing', 'online', 'science',
    'party', 'review', 'stream', 'gdn', 'accountant', 'date', 'faith',
    'win', 'bid', 'trade', 'webcam', 'christmas', 'kim', 'country',
    'work', 'ninja', 'icu'
}

# Sensitive/brand keywords that phishers often use
BRAND_KEYWORDS = [
    'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
    'instagram', 'twitter', 'netflix', 'linkedin', 'dropbox', 'yahoo',
    'ebay', 'walmart', 'chase', 'bank', 'wellsfargo', 'citibank',
    'bankofamerica', 'visa', 'mastercard', 'amex', 'americanexpress',
    'irs', 'gov', 'dhl', 'fedex', 'ups', 'usps', 'steam', 'epic'
]

# Phishing-related keywords in path/query
PHISHING_PATH_KEYWORDS = [
    'login', 'signin', 'sign-in', 'account', 'secure', 'update',
    'verify', 'verification', 'password', 'credential', 'billing',
    'payment', 'confirm', 'authenticate', 'unlock', 'recovery',
    'suspend', 'suspended', 'limited', 'validate', 'unusual', 'activity'
]


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(entropy, 4)


def extract_features(url: str) -> dict:
    """
    Extract all features from a URL.
    Returns a dict of feature_name -> (value, description, is_suspicious)
    """
    # Ensure scheme is present for parsing
    if not url.startswith(('http://', 'https://')):
        parsed_url = urllib.parse.urlparse('http://' + url)
    else:
        parsed_url = urllib.parse.urlparse(url)

    full_url = url
    scheme = parsed_url.scheme.lower()
    netloc = parsed_url.netloc.lower()
    path = parsed_url.path.lower()
    query = parsed_url.query.lower()
    fragment = parsed_url.fragment.lower()

    # Strip port from netloc for domain analysis
    hostname = netloc.split(':')[0] if ':' in netloc else netloc

    # Split domain into parts
    parts = hostname.split('.')
    domain = parts[-2] if len(parts) >= 2 else hostname
    tld = parts[-1] if len(parts) >= 1 else ''
    subdomains = parts[:-2] if len(parts) > 2 else []

    features = {}

    # ── 1. URL Length ──────────────────────────────────────────
    url_len = len(full_url)
    features['url_length'] = {
        'value': url_len,
        'label': 'URL Length',
        'description': f'Length of the full URL is {url_len} characters',
        'suspicious': url_len > 75,
        'weight': 3 if url_len > 100 else (1 if url_len > 75 else 0)
    }

    # ── 2. HTTPS ────────────────────────────────────────────────
    has_https = scheme == 'https'
    features['uses_https'] = {
        'value': has_https,
        'label': 'HTTPS Protocol',
        'description': 'URL uses HTTPS (encrypted connection)' if has_https else 'URL does NOT use HTTPS — potential security risk',
        'suspicious': not has_https,
        'weight': 2 if not has_https else 0
    }

    # ── 3. IP Address in Domain ─────────────────────────────────
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$|'
        r'^\[[\da-fA-F:]+\]$'
    )
    has_ip = bool(ip_pattern.match(hostname))
    features['ip_in_domain'] = {
        'value': has_ip,
        'label': 'IP Address as Domain',
        'description': 'Domain uses an IP address instead of a hostname' if has_ip else 'Domain uses a proper hostname',
        'suspicious': has_ip,
        'weight': 5 if has_ip else 0
    }

    # ── 4. URL Shortener ────────────────────────────────────────
    is_shortener = hostname in URL_SHORTENERS
    features['url_shortener'] = {
        'value': is_shortener,
        'label': 'URL Shortener',
        'description': f'{hostname} is a known URL shortening service' if is_shortener else 'Not a known URL shortener',
        'suspicious': is_shortener,
        'weight': 4 if is_shortener else 0
    }

    # ── 5. @ Symbol ─────────────────────────────────────────────
    has_at = '@' in full_url
    features['has_at_symbol'] = {
        'value': has_at,
        'label': '@ Symbol in URL',
        'description': 'URL contains @ symbol, browser ignores everything before it' if has_at else 'No @ symbol found',
        'suspicious': has_at,
        'weight': 5 if has_at else 0
    }

    # ── 6. Double Slash Redirect ────────────────────────────────
    has_double_slash = '//' in path
    features['double_slash_redirect'] = {
        'value': has_double_slash,
        'label': 'Double Slash Redirect',
        'description': 'Path contains // which may indicate redirect tricks' if has_double_slash else 'No suspicious double slashes',
        'suspicious': has_double_slash,
        'weight': 3 if has_double_slash else 0
    }

    # ── 7. Hyphen in Domain ─────────────────────────────────────
    hyphen_count = domain.count('-')
    features['hyphen_count'] = {
        'value': hyphen_count,
        'label': 'Hyphens in Domain',
        'description': f'Domain "{domain}" contains {hyphen_count} hyphen(s)',
        'suspicious': hyphen_count >= 2,
        'weight': min(hyphen_count, 4) if hyphen_count >= 2 else 0
    }

    # ── 8. Subdomain Depth ──────────────────────────────────────
    subdomain_depth = len(subdomains)
    features['subdomain_depth'] = {
        'value': subdomain_depth,
        'label': 'Subdomain Depth',
        'description': f'URL has {subdomain_depth} subdomain level(s): {".".join(subdomains) if subdomains else "none"}',
        'suspicious': subdomain_depth >= 3,
        'weight': min(subdomain_depth * 2, 6) if subdomain_depth >= 3 else (1 if subdomain_depth >= 2 else 0)
    }

    # ── 9. Suspicious TLD ───────────────────────────────────────
    is_suspicious_tld = tld in SUSPICIOUS_TLDS
    features['suspicious_tld'] = {
        'value': is_suspicious_tld,
        'label': 'Suspicious TLD',
        'description': f'.{tld} is a free/high-risk TLD often used in phishing' if is_suspicious_tld else f'.{tld} is a normal TLD',
        'suspicious': is_suspicious_tld,
        'weight': 4 if is_suspicious_tld else 0
    }

    # ── 10. Brand Keywords in Domain ────────────────────────────
    found_brands = [kw for kw in BRAND_KEYWORDS if kw in hostname and kw not in domain.replace('-', '')]
    has_brand_keywords = len(found_brands) > 0
    # Also check if brand keyword exists but domain is NOT the brand itself
    brand_mismatch = [kw for kw in BRAND_KEYWORDS if kw in hostname and domain != kw]
    features['brand_keywords_in_domain'] = {
        'value': found_brands,
        'label': 'Brand Keywords in Domain',
        'description': f'Detected brand keywords in subdomain/domain: {", ".join(brand_mismatch)}' if brand_mismatch else 'No suspicious brand keywords found in domain',
        'suspicious': len(brand_mismatch) > 0,
        'weight': min(len(brand_mismatch) * 3, 9) if brand_mismatch else 0
    }

    # ── 11. Phishing Keywords in Path ───────────────────────────
    found_path_kws = [kw for kw in PHISHING_PATH_KEYWORDS if kw in path or kw in query]
    features['phishing_path_keywords'] = {
        'value': found_path_kws,
        'label': 'Phishing Keywords in Path/Query',
        'description': f'Suspicious keywords found: {", ".join(found_path_kws)}' if found_path_kws else 'No phishing keywords in path/query',
        'suspicious': len(found_path_kws) > 0,
        'weight': min(len(found_path_kws) * 2, 8) if found_path_kws else 0
    }

    # ── 12. Digit Count in Domain ───────────────────────────────
    digit_count = sum(c.isdigit() for c in domain)
    features['digits_in_domain'] = {
        'value': digit_count,
        'label': 'Digits in Domain Name',
        'description': f'Domain "{domain}" has {digit_count} digit(s)',
        'suspicious': digit_count >= 3,
        'weight': min(digit_count, 4) if digit_count >= 3 else 0
    }

    # ── 13. Special Characters in URL ───────────────────────────
    special_chars = re.findall(r'[!$&\'()*+,;=%~`]', full_url)
    special_count = len(special_chars)
    features['special_char_count'] = {
        'value': special_count,
        'label': 'Special Characters in URL',
        'description': f'URL contains {special_count} special character(s)',
        'suspicious': special_count > 4,
        'weight': min(special_count // 2, 4) if special_count > 4 else 0
    }

    # ── 14. Non-standard Port ───────────────────────────────────
    port = parsed_url.port
    standard_ports = {80, 443, 8080, 8443}
    has_nonstandard_port = port is not None and port not in standard_ports
    features['nonstandard_port'] = {
        'value': port,
        'label': 'Non-standard Port',
        'description': f'Uses non-standard port: {port}' if has_nonstandard_port else 'Standard port (or no port specified)',
        'suspicious': has_nonstandard_port,
        'weight': 3 if has_nonstandard_port else 0
    }

    # ── 15. Domain Entropy ──────────────────────────────────────
    entropy = shannon_entropy(domain)
    features['domain_entropy'] = {
        'value': entropy,
        'label': 'Domain Entropy (Randomness)',
        'description': f'Domain entropy is {entropy:.2f} bits — {"high randomness, possibly auto-generated" if entropy > 3.5 else "normal"}',
        'suspicious': entropy > 3.5,
        'weight': 3 if entropy > 3.8 else (1 if entropy > 3.5 else 0)
    }

    # ── 16. Query String Length ─────────────────────────────────
    query_len = len(query)
    features['query_length'] = {
        'value': query_len,
        'label': 'Query String Length',
        'description': f'Query string is {query_len} characters long',
        'suspicious': query_len > 100,
        'weight': 2 if query_len > 100 else 0
    }

    # ── 17. Number of Query Parameters ─────────────────────────
    query_params = len(urllib.parse.parse_qs(query))
    features['query_params_count'] = {
        'value': query_params,
        'label': 'Query Parameter Count',
        'description': f'URL has {query_params} query parameter(s)',
        'suspicious': query_params > 5,
        'weight': 2 if query_params > 5 else 0
    }

    # ── 18. Domain Length ───────────────────────────────────────
    domain_len = len(domain)
    features['domain_length'] = {
        'value': domain_len,
        'label': 'Domain Name Length',
        'description': f'Domain "{domain}" is {domain_len} characters long',
        'suspicious': domain_len > 20,
        'weight': 2 if domain_len > 25 else (1 if domain_len > 20 else 0)
    }

    # ── 19. Hex Encoding in URL ─────────────────────────────────
    hex_encoded = len(re.findall(r'%[0-9a-fA-F]{2}', full_url))
    features['hex_encoding'] = {
        'value': hex_encoded,
        'label': 'Hex Encoded Characters',
        'description': f'URL contains {hex_encoded} hex-encoded character(s) — may be obfuscating content',
        'suspicious': hex_encoded > 3,
        'weight': 2 if hex_encoded > 5 else (1 if hex_encoded > 3 else 0)
    }

    # ── 20. Redirect Pattern (multiple URLs) ────────────────────
    url_count_in_url = len(re.findall(r'https?://', full_url))
    has_redirect = url_count_in_url > 1
    features['url_in_url'] = {
        'value': url_count_in_url,
        'label': 'Embedded URL (Redirect)',
        'description': f'URL contains {url_count_in_url} embedded URL(s) — possible redirect chain' if has_redirect else 'No embedded URLs detected',
        'suspicious': has_redirect,
        'weight': 5 if has_redirect else 0
    }

    return features
