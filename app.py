"""
Flask Application — Phishing URL Detection System
Main entry point for the web server
"""

from flask import Flask, render_template, request, jsonify
from detector.url_analyzer import analyze_url
from datetime import datetime
import json
import os

app = Flask(__name__)

# In-memory history store (last 50 scans)
scan_history = []
stats = {
    'total_scans': 0,
    'phishing_detected': 0,
    'suspicious_detected': 0,
    'safe_detected': 0
}


@app.route('/')
def index():
    """Serve the main page."""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def api_analyze():
    """
    POST /api/analyze
    Body: { "url": "<url_to_check>" }
    Returns full analysis report as JSON.
    """
    data = request.get_json(silent=True) or {}
    url = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    result = analyze_url(url)

    if 'error' in result:
        return jsonify(result), 400

    # Update stats
    stats['total_scans'] += 1
    verdict = result['risk']['verdict']
    if verdict == 'PHISHING':
        stats['phishing_detected'] += 1
    elif verdict == 'SUSPICIOUS':
        stats['suspicious_detected'] += 1
    else:
        stats['safe_detected'] += 1

    # Add to history
    history_entry = {
        'url': url,
        'verdict': verdict,
        'score': result['score'],
        'color': result['risk']['color'],
        'icon': result['risk']['icon'],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'red_flags_count': len(result['red_flags'])
    }
    scan_history.insert(0, history_entry)
    if len(scan_history) > 50:
        scan_history.pop()

    return jsonify(result)


@app.route('/api/history', methods=['GET'])
def api_history():
    """GET /api/history — Return recent scan history."""
    return jsonify({'history': scan_history[:20]})


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """GET /api/stats — Return scan statistics."""
    return jsonify(stats)


if __name__ == '__main__':
    print("=" * 60)
    print("  [*] Phishing URL Detection System")
    print("  [*] Server running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host='0.0.0.0', port=5000)
