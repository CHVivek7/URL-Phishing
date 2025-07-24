#https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt
# you can use this file to test a URL in website

from flask import Flask, render_template, request
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import tldextract
import validators

app = Flask(__name__)

# Load the trained model and preprocessing objects
try:
    pipeline = joblib.load('classifier.pkl')
    model = pipeline['model']  # This is the actual model
    imputer = pipeline['imputer']
    scaler = pipeline['scaler']
    selector = pipeline['selector']
    feature_names = pipeline['feature_names']
except Exception as e:
    raise Exception(f"Error loading model: {str(e)}")

def extract_features(url):
    """Extract the same features used during training"""
    if not validators.url(url):
        raise ValueError("Invalid URL format")
    
    # Ensure URL starts with http:// or https://
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    domain = parsed.netloc
    ext = tldextract.extract(url)
    
    features = {
        'DomainLength': len(domain),
        'SubdomainCount': domain.count('.'),
        'HasHyphen': int('-' in domain),
        'HasDigits': int(any(c.isdigit() for c in domain)),
        'TLD_Risk': 0.5  # Default value
    }
    
    # Add TLD risk (same mapping as in training)
    tld_risk = {'.com':0, '.org':0, '.net':0, '.tk':1, '.gq':1, '.ga':1, '.ml':1, '.cf':1, '.cc':0.7, '.pw':0.8}
    features['TLD_Risk'] = tld_risk.get(f'.{ext.suffix}', 0.5)
    
    # Ensure correct feature order
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
            # Extract and preprocess features
            features = extract_features(url)
            features_imputed = imputer.transform(features)
            features_scaled = scaler.transform(features_imputed)
            features_selected = selector.transform(features_scaled)
            
            # Predict (using the actual model, not the pipeline dictionary)
            proba = model.predict_proba(features_selected)[0]
            prediction = model.predict(features_selected)[0]
            
            # Prepare results
            probabilities = {
                'legitimate': round(proba[0]*100, 1),
                'phishing': round(proba[1]*100, 1)
            }
            
            if prediction == 0:
                result_class = 'legitimate'
                prediction_text = "This URL appears to be legitimate"
            else:
                result_class = 'phishing'
                prediction_text = "Warning! This URL appears to be phishing"
            
            return render_template('index.html',
                                prediction_text=prediction_text,
                                result_class=result_class,
                                probabilities=probabilities)
            
        except Exception as e:
            return render_template('index.html',
                                prediction_text=f"Error: {str(e)}",
                                result_class='error')
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)