from flask import Flask, render_template, request
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import tldextract
import validators
import requests
import re

app = Flask(__name__)

# Enhanced Configuration
app.config.update({
    'THREAT_FEEDS': {
        'phishtank': "https://data.phishtank.com/data/online-valid.json",
    },
    'PHISHING_KEYWORDS': ["login", "verify", "secure", "account", "update", "security", "alert"],
    'RISKY_TLDS': ['.tk', '.gq', '.ml', '.cf', '.xyz', '.top', '.cc', '.pw', '.buzz', '.onion'],
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
    """Follow redirects to get final URL"""
    try:
        session = requests.Session()
        resp = session.head(url, allow_redirects=True, timeout=5)
        return resp.url
    except:
        return url  # Return original if unshortening fails

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
    
    report = {
        "is_onion": ext.suffix == ".onion",
        "in_phish_tank": check_phish_tank(url),
        "suspicious_keywords": [
            kw for kw in app.config['PHISHING_KEYWORDS'] 
            if kw in domain
        ],
        "brand_misuse": any(
            brand in domain and not domain.endswith(f"{brand}.com")
            for brand in app.config['BRANDS']
        ),
        "risky_tld": ext.suffix in app.config['RISKY_TLDS'],
        "is_shortened": any(
            shortener in domain 
            for shortener in app.config['SHORTENERS']
        )
    }

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
    
    if len(report_lines) == 1:
        report_lines.append("✅ No explicit threats detected in databases")

    return "\n".join(report_lines)

def is_high_risk_url(url):
    """Rule-based pre-check before model prediction"""
    domain = urlparse(url).netloc.lower()
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
    
    return False

def extract_features(url):
    """Enhanced feature extraction with unshortening"""
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

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        
        if not url:
            return render_template('index.html', 
                                prediction_text="Please enter a URL",
                                result_class='error')
        
        try:
            # Rule-based pre-check
            if is_high_risk_url(url):
                return render_template('index.html',
                                    prediction_text="Warning! Phishing URL detected",
                                    result_class='phishing',
                                    probabilities={'legitimate': 10, 'phishing': 90},
                                    darkweb_output=generate_darkweb_report(url))
            
            # Model prediction
            features = extract_features(url)
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
            darkweb_output = generate_darkweb_report(url) if prediction == 1 else None
            
            return render_template('index.html',
                                prediction_text=prediction_text,
                                result_class=result_class,
                                probabilities=probabilities,
                                darkweb_output=darkweb_output)
            
        except Exception as e:
            return render_template('index.html',
                                prediction_text=f"Error: {str(e)}",
                                result_class='error')
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)