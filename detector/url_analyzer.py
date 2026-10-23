"""
URL Analyzer Module — Main analysis pipeline
Combines feature extraction and risk scoring to produce a final verdict.
"""

from .feature_extractor import extract_features


# Risk thresholds
SAFE_THRESHOLD = 20
SUSPICIOUS_THRESHOLD = 45
MAX_POSSIBLE_SCORE = 80   # approximate cap for normalization


def calculate_risk_score(features: dict) -> int:
    """Sum weighted scores from all features; clamp to [0, 100]."""
    raw = sum(f.get('weight', 0) for f in features.values())
    # Normalize to 0-100 scale
    normalized = min(int((raw / MAX_POSSIBLE_SCORE) * 100), 100)
    return normalized


def classify_risk(score: int) -> dict:
    """Return verdict, label, and color based on risk score."""
    if score < SAFE_THRESHOLD:
        return {
            'verdict': 'SAFE',
            'label': 'Safe',
            'color': '#00e676',
            'icon': '✅',
            'message': 'This URL appears to be legitimate and safe to visit.',
            'recommendation': 'No immediate threats detected. Always stay cautious when entering personal information.'
        }
    elif score < SUSPICIOUS_THRESHOLD:
        return {
            'verdict': 'SUSPICIOUS',
            'label': 'Suspicious',
            'color': '#ffab00',
            'icon': '⚠️',
            'message': 'This URL has some suspicious characteristics. Proceed with caution.',
            'recommendation': 'Do not enter any personal or financial information. Verify the source independently.'
        }
    else:
        return {
            'verdict': 'PHISHING',
            'label': 'Phishing Detected',
            'color': '#ff1744',
            'icon': '🚨',
            'message': 'This URL shows strong indicators of being a phishing attempt!',
            'recommendation': 'Do NOT visit this URL. Report it to your IT/security team immediately.'
        }


def analyze_url(url: str) -> dict:
    """
    Main entry point for URL analysis.
    Returns a complete analysis report.
    """
    url = url.strip()
    if not url:
        return {'error': 'Empty URL provided'}

    # Basic URL validation
    import re
    if not re.match(r'^(https?://)?[^\s/$.?#].[^\s]*$', url, re.IGNORECASE):
        return {'error': 'Invalid URL format'}

    features = extract_features(url)
    score = calculate_risk_score(features)
    risk = classify_risk(score)

    # Build summary of red flags
    red_flags = [
        {'label': f['label'], 'description': f['description'], 'weight': f['weight']}
        for f in features.values()
        if f.get('suspicious') and f.get('weight', 0) > 0
    ]
    red_flags.sort(key=lambda x: x['weight'], reverse=True)

    # Suspicious feature count
    suspicious_count = sum(1 for f in features.values() if f.get('suspicious'))

    return {
        'url': url,
        'score': score,
        'risk': risk,
        'features': features,
        'red_flags': red_flags,
        'suspicious_count': suspicious_count,
        'total_features': len(features),
        'summary': {
            'risk_level': risk['verdict'],
            'score': score,
            'red_flags_count': len(red_flags),
            'message': risk['message'],
            'recommendation': risk['recommendation']
        }
    }
