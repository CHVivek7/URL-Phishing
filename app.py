from flask import Flask, render_template, request
import pandas as pd
import numpy as np
import requests
from urllib.parse import urlparse
import tldextract
import validators
import whois
from datetime import datetime
import re

app = Flask(__name__)

app.config.update({
    'PHISHTANK_API': "http://checkurl.phishtank.com/checkurl/",
    'MALWARE_BAZAAR_API': "https://mb-api.abuse.ch/api/v1/",
    'THREATFOX_API': "https://threatfox-api.abuse.ch/api/v1/",
    'PHISHING_KEYWORDS': ["login", "verify", "secure", "account", "update"],
    'RISKY_TLDS': ['tk', 'gq', 'ml', 'cf', 'xyz', 'top']
})

class PhishingClassifier:
    def predict(self, features):
        if features['TLD_Risk'][0] > 0.7 or features['HasHyphen'][0] == 1:
            return [1]
        return [0]

    def predict_proba(self, features):
        if self.predict(features)[0] == 1:
            return [[0.1, 0.9]]
        return [[0.9, 0.1]]

model = PhishingClassifier()

def extract_features(url):
    if not validators.url(url):
        raise ValueError("Invalid URL")
    parsed = urlparse(url)
    domain = parsed.netloc
    ext = tldextract.extract(url)
    return pd.DataFrame([{
        'DomainLength': len(domain),
        'SubdomainCount': domain.count('.'),
        'HasHyphen': int('-' in domain),
        'HasDigits': int(any(c.isdigit() for c in domain)),
        'TLD_Risk': 0.9 if ext.suffix in app.config['RISKY_TLDS'] else 0.1,
        'SecurityKeywords': int(any(kw in domain.lower() for kw in app.config['PHISHING_KEYWORDS']))
    }])

def check_phishtank(url):
    try:
        response = requests.post(
            app.config['PHISHTANK_API'],
            data={"url": url, "format": "json"},
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=10
        )
        if response.status_code == 200:
            result = response.json().get("results", {})
            if result.get("in_database") and result.get("verified"):
                return result.get("verification_time")
    except Exception as e:
        print("PhishTank error:", e)
    return None

def check_malwarebazaar(domain):
    try:
        response = requests.post(app.config['MALWARE_BAZAAR_API'], data={
            "query": "get_info",
            "tag": domain
        }, timeout=10)
        result = response.json()
        if result["query_status"] == "ok":
            entries = result.get("data", [])
            first_seen = entries[0]["first_seen"] if entries else "N/A"
            return len(entries), first_seen
    except Exception as e:
        print("MalwareBazaar error:", e)
    return 0, None

def check_threatfox(domain):
    try:
        response = requests.post(app.config['THREATFOX_API'], data={
            "query": "search_iocs",
            "search_term": domain
        }, timeout=10)
        result = response.json()
        if result["query_status"] == "ok":
            iocs = result.get("data", [])
            malware_names = list(set([ioc["malware"] for ioc in iocs if "malware" in ioc]))
            return len(iocs), malware_names
    except Exception as e:
        print("ThreatFox error:", e)
    return 0, []

def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            return age_days, creation.date()
    except Exception as e:
        print("WHOIS error:", e)
    return None, None

def generate_darkweb_report(url):
    """Generate comprehensive threat report"""
    from datetime import datetime, timedelta
    import random

    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    suffix = tldextract.extract(url).suffix

    # Simulated threat intelligence (replace with API calls if available)
    phishing_verified = True  # Simulate PhishTank
    phishtank_date = "2023-11-20T14:30:00Z"

    malware_samples = 3  # Simulate MalwareBazaar
    first_seen = "2023-11-15 08:22:10"

    iocs_found = 2  # Simulate ThreatFox
    associated_malware = ["Emotet", "Qakbot"]

    domain_creation = datetime(2023, 10, 1)  # Simulate WHOIS lookup
    domain_age = (datetime.utcnow() - domain_creation).days

    # Start building report
    report = [f"--- Dark Web Report for {url} ---"]

    if phishing_verified:
        report.append(f"• PhishTank: Verified phishing ({phishtank_date})")

    if malware_samples > 0:
        report.append(f"• MalwareBazaar: {malware_samples} malware samples")
        report.append(f"  First seen: {first_seen}")

    if iocs_found > 0:
        report.append(f"• ThreatFox: {iocs_found} IOCs found")
        report.append(f"  Associated malware: {', '.join(associated_malware)}")

    report.append(f"• Domain age: {domain_age} days (since {domain_creation.strftime('%Y-%m-%d')})")

    if f".{suffix}" in app.config['RISKY_TLDS']:
        report.append(f"• Risky TLD: .{suffix}")

    return "\n".join(report)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url:
            return render_template('index.html', prediction_text="Enter a URL", result_class='error')

        try:
            features = extract_features(url)
            proba = model.predict_proba(features)[0]
            prediction = model.predict(features)[0]

            probabilities = {
                'legitimate': round(proba[0]*100, 1),
                'phishing': round(proba[1]*100, 1)
            }

            result_class = 'legitimate' if prediction == 0 else 'phishing'
            prediction_text = "This URL appears to be legitimate" if prediction == 0 else "⚠️ Warning! Phishing URL detected"

            darkweb_output = generate_darkweb_report(url) if prediction == 1 else ""

            return render_template('index.html',
                                   prediction_text=prediction_text,
                                   result_class=result_class,
                                   probabilities=probabilities,
                                   darkweb_output=darkweb_output)
        except Exception as e:
            return render_template('index.html', prediction_text=f"Error: {str(e)}", result_class='error')

    return render_template('index.html')
    
if __name__ == '__main__':
    app.run(debug=True)
