import re
import urllib.parse
import tldextract
import numpy as np
import pandas as pd
import validators

def preprocess_url(url, feature_names):
    """
    Extracts 25 phishing detection features from a URL.
    
    Args:
        url (str): The URL to extract features from.
        feature_names (list): A list of feature names in the exact order
                              expected by the trained model.
                              This ensures the DataFrame columns are correctly ordered.
                               
    Returns:
        pandas.DataFrame: A DataFrame with one row and columns matching feature_names.
    """
    if not validators.url(url):
        raise ValueError("Invalid URL format provided.")

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment
    ext = tldextract.extract(url)
    
    features_dict = {}

    # Feature 1: IP Address in hostname
    ip_pattern_v4 = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    ip_pattern_v6 = r"^\[(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\]$"
    features_dict['IP_Address'] = -1 if re.match(ip_pattern_v4, domain) or re.match(ip_pattern_v6, domain) else 1
    
    # Feature 2: URL Length
    features_dict['URL_Length'] = -1 if len(url) > 75 else (0 if len(url) > 54 else 1)
    
    # Feature 3: URL Shortening (common shorteners)
    shorteners = ["bit.ly", "goo.gl", "tinyurl.com", "is.gd", "t.co", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "cli.gs"]
    features_dict['URL_Shortening'] = -1 if any(s in domain for s in shorteners) else 1
    
    # Feature 4: @ Symbol in URL (used to embed credentials or confuse users)
    features_dict['Has_At_Symbol'] = -1 if "@" in url else 1
    
    # Feature 5: Hyphen in Domain (common in phishing to separate legitimate-looking words)
    features_dict['Has_Hyphen_In_Domain'] = -1 if '-' in domain else 1
    
    # Feature 6: Subdomains (more granular - adjusted from original 0/1/-1 scale)
    sub_count = ext.subdomain.count('.')
    features_dict['Subdomain_Count_Feature'] = -1 if sub_count >= 2 else (0 if sub_count == 0 else 1)
    
    # Feature 7: HTTPS in URL (legitimate uses HTTPS, phishing might not)
    features_dict['Has_HTTPS'] = 1 if parsed.scheme == 'https' else -1

    # Feature 8: Port in URL (presence of :port, rare for legitimate public web)
    features_dict['Has_Port'] = -1 if parsed.port is not None else 1

    # Feature 9: Abnormal URL (Domain matching hostname - i.e., not an IP)
    features_dict['Abnormal_URL'] = -1 if parsed.hostname and (ext.domain not in parsed.hostname) else 1 

    # Feature 10: Redirects (Multiple slashes in path beyond the initial protocol)
    features_dict['Redirects_Multiple_Slashes'] = -1 if "//" in path else 1
    
    # Feature 11: Length of Hostname (domain part)
    features_dict['Hostname_Length'] = len(domain)

    # Feature 12: Length of Path
    features_dict['Path_Length'] = len(path)

    # Feature 13: Length of Query
    features_dict['Query_Length'] = len(query)

    # Feature 14: Length of Fragment
    features_dict['Fragment_Length'] = len(fragment)

    # Feature 15: Number of parameters in query string
    features_dict['Num_Params'] = len(query.split('&')) if query else 0

    # Feature 16: Presence of "https" or "http" as part of the domain/subdomain/path
    features_dict['Https_In_Path_Or_Subdomain'] = -1 if 'https' in ext.subdomain or 'http' in ext.subdomain or 'https' in path or 'http' in path else 1

    # Feature 17: Existence of suspicious keywords in path/query (case-insensitive)
    suspicious_keywords = [
        'login', 'signin', 'account', 'webscr', 'cmd', 'dispatch', 'update', 
        'secure', 'bank', 'paypal', 'amazon', 'ebay', 'verify', 'confirm',
        'cpanel', 'admin', 'oauth', 'token', 'microsoft', 'apple', 'google',
        'icloud', 'support', 'password'
    ]
    full_url_lower = url.lower()
    features_dict['Suspicious_Keywords'] = -1 if any(kw in full_url_lower for kw in suspicious_keywords) else 1

    # Feature 18: Risky TLD (based on commonly observed risky TLDs)
    risky_tlds = ['.tk', '.gq', '.ml', '.cf', '.xyz', '.top', '.cc', '.pw', '.online', '.site', '.fun', '.bid', '.trade', '.win', '.zip', '.club', '.gdn', '.mom', '.men']
    features_dict['TLD_Risk'] = -1 if ext.suffix in risky_tlds else 1

    # Feature 19: Punycode (IDN homograph attacks: e.g., xn--pple-43d.com looks like apple.com)
    features_dict['Has_Punycode'] = -1 if domain.startswith('xn--') else 1

    # Feature 20: Digit count in domain (high digit count can be suspicious)
    features_dict['Digits_In_Domain_Count'] = sum(c.isdigit() for c in domain)

    # Feature 21: Special characters in domain (excluding hyphens/dots)
    features_dict['Special_Chars_In_Domain'] = sum(1 for c in domain if not c.isalnum() and c not in ['.', '-'])

    # Feature 22: Entropy of hostname (higher for randomly generated domains)
    def calculate_entropy(s):
        if not s: return 0
        probabilities = [s.count(c) / len(s) for c in set(s)]
        return -sum(p * np.log2(p) for p in probabilities)
    features_dict['Hostname_Entropy'] = calculate_entropy(domain)

    # Feature 23: Number of dots in path (excessive dots can be obfuscation)
    features_dict['Dots_In_Path'] = path.count('.')

    # Feature 24: Presence of 'www' in subdomain (some phishing URLs omit this or place it strangely)
    features_dict['Has_WWW_In_Subdomain'] = 1 if 'www' in ext.subdomain else 0

    # Feature 25: Depth of path (number of directories)
    features_dict['Path_Depth'] = path.count('/') - (1 if path.startswith('/') else 0)


    # Convert the dictionary to a list of values in the order specified by feature_names
    feature_values = [features_dict.get(name, 0) for name in feature_names] 

    # Create a DataFrame with the correct column names and order
    df = pd.DataFrame([feature_values], columns=feature_names)
    
    return df