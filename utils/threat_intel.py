import os
import time
import base64
import requests
from datetime import datetime, timedelta


def _encode_url_for_vt(url: str) -> str:
    # VirusTotal v3 uses URL identifier as base64 urlsafe without padding
    b = base64.urlsafe_b64encode(url.encode()).decode()
    return b.rstrip('=')


def check_url_virustotal(url: str, timeout=10):
    """Query VirusTotal v3 for a URL report. Returns a dict or None if API key missing.

    The function will try to return a dict with keys: positives, total, first_seen, last_seen.
    If the API is unreachable or key is missing, returns None.
    """
    vt_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
    if not vt_api_key:
        return None
    vt_headers = {'x-apikey': vt_api_key}

    try:
        # POST the URL for analysis (this will queue an analysis)
        post_url = 'https://www.virustotal.com/api/v3/urls'
        resp = requests.post(post_url, headers=vt_headers, data={'url': url}, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()

        analysis_id = data.get('data', {}).get('id')
        # Poll the analysis endpoint a few times (short loop)
        analysis_url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
        for _ in range(6):
            r = requests.get(analysis_url, headers=vt_headers, timeout=timeout)
            r.raise_for_status()
            ad = r.json()
            status = ad.get('data', {}).get('attributes', {}).get('status')
            if status == 'completed':
                break
            time.sleep(1)

        # Try to fetch the URL object for stats
        encoded = _encode_url_for_vt(url)
        url_obj = requests.get(f'https://www.virustotal.com/api/v3/urls/{encoded}', headers=vt_headers, timeout=timeout)
        url_obj.raise_for_status()
        uo = url_obj.json()

        stats = uo.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        positives = stats.get('malicious', 0) + stats.get('suspicious', 0)
        total = sum(v for v in stats.values()) if stats else 0

        first_seen = uo.get('data', {}).get('attributes', {}).get('first_submission_date')
        last_seen = uo.get('data', {}).get('attributes', {}).get('last_modification_date')

        # Convert epoch timestamps if present
        def _fmt(ts):
            try:
                return datetime.utcfromtimestamp(int(ts)).isoformat() if ts else None
            except Exception:
                return None

        return {
            'positives': int(positives),
            'total': int(total),
            'first_seen': _fmt(first_seen),
            'last_seen': _fmt(last_seen)
        }

    except Exception:
        return None


def calculate_danger_score(positives: int, total: int, first_seen: str, last_seen: str) -> int:
    """Heuristic to map intel to a 1-10 danger score."""
    if positives is None or total is None:
        return 0

    base = 0
    try:
        base = int((positives / total) * 6) if total > 0 else 0
    except Exception:
        base = 0

    recency_bonus = 0
    longevity_bonus = 0
    try:
        if last_seen:
            last = datetime.fromisoformat(last_seen)
            if datetime.utcnow() - last <= timedelta(days=30):
                recency_bonus = 2
            elif datetime.utcnow() - last <= timedelta(days=180):
                recency_bonus = 1

        if first_seen:
            first = datetime.fromisoformat(first_seen)
            # Known for long time and still present
            if datetime.utcnow() - first >= timedelta(days=365):
                longevity_bonus = 2
            elif datetime.utcnow() - first >= timedelta(days=180):
                longevity_bonus = 1
    except Exception:
        pass

    score = base + recency_bonus + longevity_bonus
    if score < 1 and (positives or total):
        score = 1
    if score > 10:
        score = 10
    return score
