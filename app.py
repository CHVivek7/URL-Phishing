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
import joblib
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

# Enhanced Configuration
app.config.update({
    'THREAT_FEEDS': {
        'phishtank': "https://data.phishtank.com/data/online-valid.json",
    },
    'PHISHING_KEYWORDS': [
        "login", "verify", "secure", "account", "update", "security", "alert",
    "refund", "renew", "renewal", "subscription", "cashback", "urgent", "payment", "support", "verification"
    ],
    # tldextract.suffix returns values without a leading dot (e.g. 'com', 'co.uk', 'onion')
    'RISKY_TLDS': ['tk', 'gq', 'ml', 'cf', 'xyz', 'top', 'cc', 'pw', 'buzz', 'onion'],
    'BRANDS': [
        "paypal", "google", "amazon", "microsoft", "apple", "bank", "chase", "wellsfargo",
        "paytm", "flipkart", "netflix", "phonepe", "googlepay", "axis", "sbi", "oksbi", "ybl"
    ],
    'SHORTENERS': ["bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd"],
    'API_TIMEOUT': 5
})
# Trusted UPI payee addresses (example entries). Empty by default.
app.config['UPI_TRUSTED_PA'] = []
# Try to load a trained UPI model if present (upi_model.pkl)
try:
    upi_model = joblib.load('upi_model.pkl')
    app.config['UPI_MODEL'] = upi_model
except Exception:
    app.config['UPI_MODEL'] = None

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


def parse_upi_uri(uri: str) -> dict:
    """Parse a UPI URI like:
    upi://pay?pa=7989200801@ybl&pn=Name&mc=0000&mode=02&purpose=00
    Returns a dict of decoded query params (pa, pn, mc, mode, purpose, etc.).
    """
    try:
        if not isinstance(uri, str):
            return {}
        # ensure we don't prefix with http:// here
        parsed = urlparse(uri)
        # query may be in parsed.query; if scheme is missing parse as-is
        query = parsed.query or (uri.split('?', 1)[1] if '?' in uri else '')
        from urllib.parse import parse_qs, unquote
        qs = parse_qs(query, keep_blank_values=True)
        # flatten qs values and decode
        out = {k: unquote(v[0]) if isinstance(v, list) and v else '' for k, v in qs.items()}
        return out
    except Exception:
        return {}


def is_upi_brand_spoof(parsed_upi: dict) -> bool:
    """Detect obvious brand-spoofing patterns in a parsed UPI URI.

    Heuristics used:
    - Normalize pa/pn and split into tokens (remove punctuation except @ and .)
    - If a known brand token appears in tokens AND any suspicious token (refund/support/verify/renew/etc.)
      or hyphenated local-parts or long digit sequences appear, flag as brand-spoof.
    - Use fuzzy match on payee name (pn) vs brand if exact matches not found.
    """
    try:
        if not parsed_upi:
            return False
        pa = (parsed_upi.get('pa') or '').strip().lower()
        pn = (parsed_upi.get('pn') or '').strip().lower()
        if not pa and not pn:
            return False

        # Normalize tokens: keep alphanum and @ . - as separators
        pa_norm = re.sub(r'[^a-z0-9@.\-]', ' ', pa)
        pn_norm = re.sub(r'[^a-z0-9 ]', ' ', pn)

        pa_tokens = set(pa_norm.replace('@', ' ').replace('.', ' ').split())
        pn_tokens = set(pn_norm.split())
        tokens = pa_tokens.union(pn_tokens)

        brands = app.config.get('BRANDS', [])
        suspicious_keywords = ['refund', 'support', 'help', 'secure', 'verify', 'renew', 'subscription', 'payment', 'account']

        for brand in brands:
            if brand in tokens or any(tok == brand for tok in tokens):
                # immediate suspicious keywords
                if any(sk in pa or sk in pn for sk in suspicious_keywords):
                    return True
                # hyphenated local part (e.g., amazon-refund@paytm)
                local = pa.split('@')[0] if pa else ''
                if '-' in local or re.search(r'\d{3,}', local):
                    return True
                # fuzzy match on payee name
                if pn and difflib.SequenceMatcher(None, pn, brand).ratio() >= 0.80 and not pn.endswith(f"{brand}.com"):
                    return True
        return False
    except Exception:
        return False


def assess_upi_risk(parsed_upi: dict, trusted: bool=False) -> dict:
    """Rule-based assessment for UPI payment URIs.
    Returns a dict with 'phishing' and 'legitimate' percentages (0-100).
    This is heuristic and intended to give the user a quick indication.
    """
    # If a trained UPI model exists, use it
    model = app.config.get('UPI_MODEL')
    # Use a dedicated helper for robust UPI brand-spoof detection (normalization + fuzzy checks)
    try:
        if is_upi_brand_spoof(parsed_upi):
            return {'phishing': 99.0, 'legitimate': 1.0}
    except Exception:
        # if helper fails for any reason, continue to model/heuristics
        pass
    if model is not None:
        # Build feature vector in the same order used for training
        pa = (parsed_upi.get('pa') or '').strip()
        pn = (parsed_upi.get('pn') or '').strip()
        raw = ' '.join(parsed_upi.values())
        features = []
        features.append(1 if pa else 0)                      # pa_present
        features.append(len(pn))                             # pn_length
        features.append(1 if '%' in raw or '+' in raw else 0) # has_encoded
        features.append(len([c for c in pa if not c.isalnum() and c not in ['@','_','-','.']])) # special_char_count
        features.append(1 if pa and pa.replace('@','').isdigit() else 0) # pa_numeric
        features.append(1 if any(kw in pn.lower() for kw in app.config.get('PHISHING_KEYWORDS', [])) else 0)
        features.append(len(raw))                            # raw_length
        # brand_spoof feature: 1 if obvious brand-spoof detected, 0 otherwise
        try:
            features.append(1 if is_upi_brand_spoof(parsed_upi) else 0)
        except Exception:
            features.append(0)
        import numpy as _np
        X = _np.array([features])
        try:
            prob = model.predict_proba(X)[0]
            phish_prob = round(float(prob[1])*100, 1)
            legit_prob = round(float(prob[0])*100, 1)
            return {'phishing': phish_prob, 'legitimate': legit_prob}
        except Exception:
            # fallback to heuristics on failure
            pass

    # Fallback: use previous heuristics
    phish_score = 0

    if trusted:
        phish_score = 3
    pa = (parsed_upi.get('pa') or '').strip()
    pn = (parsed_upi.get('pn') or '').strip().lower()
    raw = ' '.join(parsed_upi.values())

    if not pa:
        phish_score += 30
    if len(raw) > 120:
        phish_score += 10
    if '%' in raw or '+' in raw:
        phish_score += 8
    if pa and pa.replace('@','').isdigit():
        phish_score += 6
    for kw in app.config.get('PHISHING_KEYWORDS', []):
        if kw in pn:
            phish_score += 15
    if any(ch in pa for ch in ['$', '!', '*', '(']):
        phish_score += 8

    phish_score = max(0, min(95, phish_score))
    phish_prob = round(phish_score, 1)
    legit_prob = round(100 - phish_prob, 1)
    return {'phishing': phish_prob, 'legitimate': legit_prob}

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

        # Special-case common non-HTTP schemes (UPI URIs, mailto, tel, etc.).
        # These are not web URLs and shouldn't be force-prefixed with http:// nor
        # sent through the URL classifier pipeline which expects http/https.
        lower_url = url.lower()
        if lower_url.startswith('upi://') or lower_url.startswith('mailto:') or lower_url.startswith('tel:'):
            final_url = url.strip()

            # If it's a UPI URI, parse fields for clearer UI and optional trust checks
            parsed_upi = None
            upi_trusted = False
            if lower_url.startswith('upi://'):
                parsed_upi = parse_upi_uri(final_url)
                pa = parsed_upi.get('pa')
                if pa and pa in app.config.get('UPI_TRUSTED_PA', []):
                    upi_trusted = True

            # Quick check at request-time: brand-spoofing pattern in parsed UPI
            brand_spoof = False
            if parsed_upi:
                try:
                    brand_spoof = is_upi_brand_spoof(parsed_upi)
                except Exception:
                    brand_spoof = False
            if brand_spoof:
                # immediately render as high-confidence phishing for UX clarity
                upi_probs = {'phishing': 95.0, 'legitimate': 5.0}
                return render_template('index.html',
                                       prediction_text='UPI payment URI detected — possible brand-spoof (high risk)',
                                       result_class='phishing',
                                       probabilities=upi_probs,
                                       darkweb_report=None,
                                       intel=None,
                                       final_url=final_url,
                                       parsed_upi=parsed_upi,
                                       upi_trusted=upi_trusted)

            # Choose a clearer prediction text depending on trust
            if lower_url.startswith('upi://'):
                if upi_trusted:
                    pred_text = 'UPI payment URI detected — trusted payee'
                    result_cls = 'legitimate'
                else:
                    pred_text = 'UPI payment URI detected — verify payee details'
                    result_cls = 'error'
            else:
                pred_text = 'Detected non-web URI (mailto/tel)'
                result_cls = 'legitimate'

            # compute UPI heuristics probabilities (or model-based) and decide result label
            upi_probs = None
            if parsed_upi:
                upi_probs = assess_upi_risk(parsed_upi, upi_trusted)

            # Set result class based on computed probabilities if available
            if upi_probs:
                try:
                    phish_p = float(upi_probs.get('phishing', 0))
                except Exception:
                    phish_p = 0.0

                # If phishing probability is high, mark as phishing; otherwise legitimate.
                if phish_p >= 50.0:
                    result_cls = 'phishing'
                    pred_text = f"UPI payment URI detected — {phish_p:.1f}% phishing probability"
                else:
                    # trusted overrides low phishing probability
                    if upi_trusted:
                        result_cls = 'legitimate'
                        pred_text = 'UPI payment URI detected — trusted payee'
                    else:
                        result_cls = 'legitimate'
                        pred_text = f"UPI payment URI detected — {upi_probs.get('legitimate', 100.0):.1f}% legitimate"

            return render_template('index.html',
                                   prediction_text=pred_text,
                                   result_class=result_cls,
                                   probabilities=upi_probs,
                                   darkweb_report=None,
                                   intel=None,
                                   final_url=final_url,
                                   parsed_upi=parsed_upi,
                                   upi_trusted=upi_trusted)

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