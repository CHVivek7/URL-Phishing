import re
import urllib.parse
import tldextract
import numpy as np

def preprocess_url(url):
    """Extract 25 phishing detection features from URL"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    features = []
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    ext = tldextract.extract(url)
    
    # Feature 1: IP Address
    ip_pattern = r"((\d{1,3}\.){3}\d{1,3})|([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){7})"
    features.append(-1 if re.search(ip_pattern, url) else 1)
    
    # Feature 2: URL Length
    features.append(-1 if len(url) > 75 else (0 if len(url) > 54 else 1))
    
    # Feature 3: URL Shortening
    shorteners = ["bit.ly", "goo.gl", "tinyurl.com", "is.gd", "t.co"]
    features.append(-1 if any(s in domain for s in shorteners) else 1)
    
    # Feature 4: @ Symbol
    features.append(-1 if "@" in url else 1)
    
    # Feature 5: - in Domain
    features.append(-1 if '-' in domain else 1)
    
    # Feature 6: Subdomains
    sub_count = ext.subdomain.count('.')
    features.append(-1 if sub_count >= 2 else (0 if sub_count == 1 else 1))
    
    # Feature 7: HTTPS
    features.append(1 if url.startswith("https://") else -1)
    
    # Features 8-13: Placeholders
    features.extend([0]*6)
    
    # Feature 14: Abnormal URL
    features.append(-1 if parsed.hostname and ext.domain not in parsed.hostname else 1)
    
    # Feature 15: Redirects
    if url.startswith(("http://", "https://")):
        url_without_proto = url.split("//", 1)[1]
        features.append(-1 if url_without_proto.count('//') > 0 else 1)
    else:
        features.append(1)
    
    # Features 16-25: Placeholders
    features.extend([0]*10)
    
    return np.array(features).reshape(1, -1)