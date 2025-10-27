from flask import Flask, render_template, request
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse, unquote
import tldextract
import validators
import requests
import difflib
import os
try:
    from dotenv import load_dotenv
    HAS_DOTENV = True
except Exception:
    HAS_DOTENV = False

# Load .env from project root (if python-dotenv is installed), otherwise fall back to manual parsing
if HAS_DOTENV:
    try:
        load_dotenv()  # loads .env in project root if exists
        load_dotenv(os.path.join(os.path.dirname(__file__), 'utils', '.env'))
    except Exception:
        pass
else:
    # Fallback: parse utils/.env manually if it's present and the var not already set
    env_path = os.path.join(os.path.dirname(__file__), 'utils', '.env')
    if os.path.exists(env_path) and not os.environ.get('VIRUSTOTAL_API_KEY'):
        try:
            with open(env_path, 'r') as f:
                for line in f:
                    if '=' not in line or line.strip().startswith('#'):
                        continue
                    k, v = line.strip().split('=', 1)
                    if k and not os.environ.get(k):
                        os.environ[k] = v
        except Exception:
            pass

from utils.qr_unshorten import decode_qr_from_file, unshorten_url as util_unshorten, is_shortened
from utils.threat_intel import check_url_virustotal, calculate_danger_score
import re

app = Flask(__name__)

# Enhanced Configuration
app.config.update({
    'THREAT_FEEDS': {
        'phishtank': "https://data.phishtank.com/data/online-valid.json",
    },
    'PHISHING_KEYWORDS': ["login", "verify", "secure", "account", "update", "security", "alert"],
    # tldextract.suffix returns values without a leading dot (e.g. 'com', 'co.uk', 'onion')
    'RISKY_TLDS': ['tk', 'gq', 'ml', 'cf', 'xyz', 'top', 'cc', 'pw', 'buzz', 'onion'],
    'BRANDS': ["paypal", "google", "amazon", "microsoft", "apple", "bank", "chase", "wellsfargo"],
    'SHORTENERS': ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd"],
    'API_TIMEOUT': 5
})

# Load the trained model
try:
    pipeline = joblib.load('classifier.pkl')
    model = pipeline['model']
    imputer = pipeline['imputer']
    scaler = pipeline['scaler']
    selector = pipeline['selector']
    feature_names = pipeline['feature_names']
except Exception as e:
    raise Exception(f"Error loading model: {str(e)}")

def unshorten_url(url):
    """Wrapper that uses utils implementation to follow redirects and resolve short URLs."""
    try:
        return util_unshorten(url)
    except Exception:
        return url


def normalize_url(url: str) -> str:
    """Normalize input URL for consistent parsing and network calls.

    - Strips surrounding whitespace
    - Adds http:// if scheme missing
    - Ensures scheme is lowercase
    - Returns the normalized string
    """
    if not isinstance(url, str):
        return url
    u = url.strip()
    if u == '':
        return u
    # Add scheme if missing
    if not u.lower().startswith(('http://', 'https://')):
        u = 'http://' + u
    # normalize scheme casing
    parts = u.split('://', 1)
    if len(parts) == 2:
        scheme, rest = parts
        u = scheme.lower() + '://' + rest
    return u

def check_phish_tank(url):
    """Check PhishTank database"""
    try:
        domain = urlparse(url).netloc
        response = requests.get(
            app.config['THREAT_FEEDS']['phishtank'],
            timeout=app.config['API_TIMEOUT']
        )
        return any(domain in entry['url'] for entry in response.json())
    except:
        return False

def generate_darkweb_report(url):
    """Generate a detailed threat report"""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    ext = tldextract.extract(url)
    
    # Detect percent-encoding obfuscation and brand similarity checks
    decoded_url = unquote(url)
    decoded_domain = urlparse(decoded_url).netloc.lower()

    report = {
        # ext.suffix returns 'onion' for .onion addresses
        "is_onion": ext.suffix == "onion" or parsed.netloc.lower().endswith('.onion'),
        "in_phish_tank": check_phish_tank(url),
        "has_percent_encoding": '%' in url,
        "suspicious_keywords": [
            kw for kw in app.config['PHISHING_KEYWORDS'] 
            if kw in domain
        ],
        "brand_misuse": any(
            brand in domain and not domain.endswith(f"{brand}.com")
            for brand in app.config['BRANDS']
        ),
        "brand_similarity": {
            brand: difflib.SequenceMatcher(None, decoded_domain, brand).ratio()
            for brand in app.config['BRANDS']
        },
    "risky_tld": ext.suffix in app.config['RISKY_TLDS'],
        "is_shortened": any(
            shortener in domain 
            for shortener in app.config['SHORTENERS']
        )
    }
    # detect suspicious repeated 'w' subdomains like 'wwww.example.com' or 'www.www.example.com'
    labels = domain.split('.')
    report['suspicious_www_repeat'] = any(re.match(r'^w{4,}$', lbl) or lbl.startswith('www') and domain.count('www')>1 for lbl in labels)

    report_lines = [f"🔍 **Threat Report for `{url}`**"]
    
    if report["is_onion"]:
        report_lines.append("⚠️ **Dark Web URL** (.onion detected)")
    
    if report["in_phish_tank"]:
        report_lines.append("⚠️ **Listed in PhishTank** (known phishing database)")
    
    if report["risky_tld"]:
        report_lines.append(f"⚠️ **Risky TLD**: `{ext.suffix}`")
    
    if report["brand_misuse"]:
        matched_brands = [
            brand for brand in app.config['BRANDS']
            if brand in domain
        ]
        report_lines.append(f"⚠️ **Brand Misuse**: {', '.join(matched_brands)}")
    
    if report["suspicious_keywords"]:
        report_lines.append(
            f"⚠️ **Suspicious Keywords**: {', '.join(report['suspicious_keywords'])}"
        )
    
    if report["is_shortened"]:
        report_lines.append("⚠️ **Shortened URL** (may hide malicious destination)")
    if report.get("has_percent_encoding"):
        report_lines.append("⚠️ **Obfuscated URL** (percent-encoding detected in URL)")
    if report.get('suspicious_www_repeat'):
        report_lines.append("⚠️ **Suspicious subdomain**: repeated 'w' or malformed www (example: 'wwww.example.com')")
    # If decoded domain is very similar to a brand but not the brand's real domain, flag it
    similar = [b for b, r in report.get('brand_similarity', {}).items() if r >= 0.75]
    for b in similar:
        if not domain.endswith(f"{b}.com"):
            report_lines.append(f"⚠️ **Brand-Spoofing**: domain similar to {b} (similarity={report['brand_similarity'][b]:.2f})")
    if len(report_lines) == 1:
        report_lines.append("✅ No explicit threats detected in databases")

    return "\n".join(report_lines)

def is_high_risk_url(url):
    """Rule-based pre-check before model prediction"""
    # Normalize and decode percent-encodings for checks
    decoded = unquote(url)
    domain = urlparse(decoded).netloc.lower()
    ext = tldextract.extract(url)
    
    # 1. Check risky TLDs (including .onion)
    if ext.suffix in app.config['RISKY_TLDS']:
        return True
    
    # 2. Check brand name misuse
    for brand in app.config['BRANDS']:
        if brand in domain and not domain.endswith(f"{brand}.com"):
            return True
    
    # 3. Check suspicious keywords
    if any(kw in domain for kw in app.config['PHISHING_KEYWORDS']):
        return True
    
    # 4. Check unusual structure
    if '--' in domain or domain.count('.') > 3:
        return True
    
    # 5. Check if URL is shortened
    if any(shortener in domain for shortener in app.config['SHORTENERS']):
        return True
    
    # 6. Explicit .onion check
    if '.onion' in domain:
        return True

    # 7. Percent-encoding obfuscation
    if '%' in url:
        return True

    # 8. Brand similarity (fuzzy match) - flag if high similarity but not actual brand domain
    decoded_domain = urlparse(unquote(url)).netloc.lower()
    for brand in app.config['BRANDS']:
        ratio = difflib.SequenceMatcher(None, decoded_domain, brand).ratio()
        if ratio >= 0.80 and not decoded_domain.endswith(f"{brand}.com"):
            return True
    # 9. Suspicious repeated 'w' subdomain (e.g., 'wwww.example.com' or 'www.www.example.com')
    labels = decoded_domain.split('.')
    for lbl in labels:
        if re.match(r'^w{4,}$', lbl):
            return True
    if decoded_domain.count('www') > 1:
        return True
    
    return False

def extract_features(url):
    """Enhanced feature extraction with unshortening"""
    # Normalize URL to ensure validators and tldextract handle it correctly
    url = normalize_url(url)
    if not validators.url(url):
        raise ValueError("Invalid URL format")
    
    # Unshorten URL first
    final_url = unshorten_url(url)
    parsed = urlparse(final_url)
    domain = parsed.netloc
    ext = tldextract.extract(final_url)
    
    features = {
        'DomainLength': len(domain),
        'SubdomainCount': domain.count('.'),
        'HasHyphen': int('-' in domain),
        'HasDigits': int(any(c.isdigit() for c in domain)),
        'TLD_Risk': 0.9 if ext.suffix in app.config['RISKY_TLDS'] else 0.1,
        'SecurityKeywords': int(any(kw in domain.lower() for kw in app.config['PHISHING_KEYWORDS'])),
        'BrandInDomain': int(any(brand in domain.lower() for brand in app.config['BRANDS'])),
        'CorrectBrandDomain': int(any(domain.endswith(f"{brand}.com") for brand in app.config['BRANDS'])),
        'IsShortened': int(any(shortener in domain for shortener in app.config['SHORTENERS'])),
        'IsOnion': int('.onion' in domain)
    }
    
    return pd.DataFrame([features], columns=feature_names)


def run_threat_intel(final_url):
    """Query configured threat intel (VirusTotal if key present) and compute danger score."""
    vt = check_url_virustotal(final_url)
    if not vt:
        return None

    positives = vt.get('positives', 0)
    total = vt.get('total', 0)
    first = vt.get('first_seen')
    last = vt.get('last_seen')
    score = calculate_danger_score(positives, total, first, last)

    descriptor = 'Unknown'
    if score >= 9:
        descriptor = 'Critical Risk'
    elif score >= 7:
        descriptor = 'High Risk'
    elif score >= 4:
        descriptor = 'Medium Risk'
    else:
        descriptor = 'Low Risk'

    return {
        'danger_score': score,
        'positives': positives,
        'total': total,
        'first_seen': first,
        'last_seen': last,
        'descriptor': descriptor
    }


def adjust_intel_for_display(intel, result_class):
    """Adjust intel dict for display rules:
    - If legitimate: show danger < 3 and hide threat counts (but keep first_seen).
    - If phishing: add +2 to danger score and apply modulo 10; map 0 to 10.
    Returns a new dict safe for template rendering.
    """
    if not intel:
        return None

    # copy to avoid mutating original
    it = dict(intel)

    try:
        score = int(it.get('danger_score', 0))
    except Exception:
        score = 0

    if result_class == 'legitimate':
        # cap to less than 3
        if score >= 3:
            it['danger_score'] = 2
        else:
            it['danger_score'] = score if score > 0 else 1
        # hide vendor counts and descriptor
        it['positives'] = 0
        it['total'] = 0
        it['descriptor'] = 'Low Risk'
        # keep first_seen/last_seen as-is
        return it

    if result_class == 'phishing':
        # add +2 and apply modulo 10
        new_score = (score + 2) % 10
        if new_score == 0:
            new_score = 10
        it['danger_score'] = new_score
        # update descriptor based on new score
        if new_score >= 9:
            it['descriptor'] = 'Critical Risk'
        elif new_score >= 7:
            it['descriptor'] = 'High Risk'
        elif new_score >= 4:
            it['descriptor'] = 'Medium Risk'
        else:
            it['descriptor'] = 'Low Risk'
        return it

    return it

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        # If an image was uploaded (from QR capture), try to decode server-side
        try:
            if 'qrImage' in request.files:
                f = request.files.get('qrImage')
                if f and getattr(f, 'filename', ''):
                    decoded = decode_qr_from_file(f.stream or f)
                    if decoded:
                        url = decoded.strip()
        except Exception:
            # Non-fatal: continue with the provided URL
            pass

        if not url:
            return render_template('index.html', 
                                prediction_text="Please enter a URL",
                                result_class='error')

        try:
            # Normalize input and resolve short links early to analyze the final destination
            url = normalize_url(url)
            final_url = unshorten_url(url)

            # Prepare intel variable (may be None if API key missing)
            intel = None

            # Rule-based pre-check on final (unshortened) URL. Presence of a shortener
            # will be reported but does not by itself mark the URL as phishing.
            if is_high_risk_url(final_url):
                intel = run_threat_intel(final_url)
                darkweb_report = generate_darkweb_report(final_url)
                # adjust intel according to display rules (rule-based branch is phishing)
                intel = adjust_intel_for_display(intel, 'phishing')

                # Build exact summary text block
                pred_label = 'LIKELY PHISHING'
                confidence = 90
                summary_lines = [
                    '✅ URL Analysis Complete!',
                    '',
                    f'🔗 Final URL: {final_url}',
                    f'🤖 Phishing Detection: **{pred_label}** ({confidence}% confidence)',
                    '💀 Threat Intelligence:'
                ]
                if intel:
                    summary_lines.append(f"   - Danger Score: {intel['danger_score']}/10 ({intel['descriptor']})")
                    summary_lines.append(f"   - Estimated Impact: Flagged by {intel['positives']}/{intel['total']} security vendors.")
                    if intel.get('first_seen'):
                        summary_lines.append(f"   - First Seen: {intel.get('first_seen')[:10]}")
                else:
                    summary_lines.append('   - Danger Score: Unknown')
                    summary_lines.append('   - Estimated Impact: Unknown')

                # Warning line
                summary_lines.append('⚠️ Warning: This URL has a strong association with known malicious activity.')
                summary_text = "\n".join(summary_lines)

                return render_template('index.html',
                                    prediction_text="Warning! Phishing URL detected",
                                    result_class='phishing',
                                    probabilities={'legitimate': 10, 'phishing': 90},
                                    darkweb_report=darkweb_report,
                                    intel=intel,
                                    final_url=final_url,
                                    summary_text=summary_text)

            # Model prediction
            features = extract_features(final_url)
            features_imputed = imputer.transform(features)
            features_scaled = scaler.transform(features_imputed)
            features_selected = selector.transform(features_scaled)

            proba = model.predict_proba(features_selected)[0]
            prediction = model.predict(features_selected)[0]

            # Prepare response
            probabilities = {
                'legitimate': round(proba[0]*100, 1),
                'phishing': round(proba[1]*100, 1)
            }

            result_class = 'legitimate' if prediction == 0 else 'phishing'
            prediction_text = "This URL appears to be legitimate" if prediction == 0 else "Warning! Phishing URL detected"

            # Generate report for phishing URLs
            darkweb_report = generate_darkweb_report(final_url) if prediction == 1 else None

            # Run threat intelligence (if key configured)
            intel = run_threat_intel(final_url)
            # Adjust intel display according to model prediction
            intel = adjust_intel_for_display(intel, result_class)

            # Build exact summary text block to match requested format
            pred_label = 'LIKELY PHISHING' if result_class == 'phishing' else 'LIKELY LEGITIMATE'
            conf_val = int(round(probabilities['phishing'])) if result_class == 'phishing' else int(round(probabilities['legitimate']))
            summary_lines = [
                '✅ URL Analysis Complete!',
                '',
                f'🔗 Final URL: {final_url}',
                f'🤖 Phishing Detection: **{pred_label}** ({conf_val}% confidence)',
                '💀 Threat Intelligence:'
            ]
            if intel:
                summary_lines.append(f"   - Danger Score: {intel['danger_score']}/10 ({intel['descriptor']})")
                summary_lines.append(f"   - Estimated Impact: Flagged by {intel['positives']}/{intel['total']} security vendors.")
                if intel.get('first_seen'):
                    summary_lines.append(f"   - First Seen: {intel['first_seen'][:10]}")
            else:
                summary_lines.append('   - Danger Score: Unknown')
                summary_lines.append('   - Estimated Impact: Unknown')

            warn = (result_class == 'phishing') or (intel and intel.get('danger_score') and intel.get('danger_score') >= 7)
            if warn:
                summary_lines.append('⚠️ Warning: This URL has a strong association with known malicious activity.')

            summary_text = "\n".join(summary_lines)

            return render_template('index.html',
                                prediction_text=prediction_text,
                                result_class=result_class,
                                probabilities=probabilities,
                                darkweb_report=darkweb_report,
                                intel=intel,
                                final_url=final_url,
                                summary_text=summary_text)

        except Exception as e:
            return render_template('index.html',
                                prediction_text=f"Error: {str(e)}",
                                result_class='error')
    
    return render_template('index.html')

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)