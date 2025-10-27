# 🚨 URL Phishing Detector — Machine Learning Powered

[Live Demo](https://url-phishing-qddg.onrender.com/) • [Repository](https://github.com/CHVivek7/URL-Phishing) • License: MIT

A fast, easy-to-use machine learning system to detect phishing URLs. It extracts meaningful URL and webpage features, feeds them into trained classifiers, and predicts whether a URL is legitimate or phishing — all wrapped in a friendly Flask web interface and an exploratory Jupyter notebook.

Why this project?
- Phishing remains one of the most effective attack vectors for stealing credentials and personal data. Automating detection reduces human risk and improves response time.
- Lightweight, explainable features (HTTPS presence, anchor patterns, domain tokens, traffic signals) make it practical for integration into tooling and web apps.

---

## ✨ Highlights

- 🔎 Feature-based detection using URL and page attributes  
- ⚡ Fast inference with saved models (joblib)  
- 🌐 Flask web app for easy testing and demoing  
- 📓 Jupyter notebook for exploration, feature engineering and model evaluation  
- 🧭 Clean code and modular feature extraction for easy extension

---

## 🔧 Quick Start — Run locally

Clone the repo and install dependencies:

```bash
git clone https://github.com/CHVivek7/URL-Phishing.git
cd URL-Phishing
pip install -r requirements.txt
# or: pip install flask pandas numpy scikit-learn joblib
```

Run the web app:

```bash
python app.py
```

Open http://127.0.0.1:5000/ in your browser and paste a URL to check it.

---

## 🧠 How it works (overview)

1. Extract URL- and HTML-derived features:
   - Protocol (http/https)
   - Presence of IP address or uncommon characters in domain
   - Tokenization of domain and path
   - Anchor tag characteristics (suspicious links, many empty anchors)
   - WHOIS/traffic signals when available
2. Transform and scale features; apply saved ML model
3. Return prediction: "Legitimate" or "Phishing" with confidence score
4. Web UI displays result and key feature highlights for explainability

---

## 📂 What’s in the repo

- app.py — Flask application (web UI + REST endpoint)  
- Phishing_URL_Detection.ipynb — Notebook: EDA, feature engineering, model training & evaluation  
- requirements.txt — Python dependencies  
- models/ — (optional) saved model files (joblib)  
- utils/ or helpers/ — feature extraction and preprocessing modules

---

## 🧪 Example: API usage

The app exposes a simple form. There’s also an API-style example (if you want to call the model programmatically):

```bash
curl -X POST "http://127.0.0.1:5000/predict" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://example.com/login"}'
```

Response (JSON):

```json
{
  "url": "http://example.com/login",
  "prediction": "Legitimate",
  "confidence": 0.97,
  "explanations": {
    "uses_https": false,
    "suspicious_anchor_ratio": 0.05,
    "token_entropy": 1.3
  }
}
```

---

## 🧭 Notebook: Explore & Improve

Open `Phishing_URL_Detection.ipynb` to:
- Inspect dataset and label distribution
- See which features contribute most to predictions
- Re-train models (Random Forest, XGBoost, etc.) and compare metrics
- Export a tuned model using joblib for deployment

---

## ✅ Tips for improving detection

- Add URL reputation and passive DNS signals for more context
- Use WHOIS age and registration metadata
- Combine model outputs with browser-based heuristics for client-side warnings
- Continuously retrain on fresh phishing URLs to adapt to attacker tactics

---

## 🤝 Contributing

Contributions, issues and feature requests are welcome!

1. Fork the repo  
2. Create a feature branch: git checkout -b feature/my-feature  
3. Commit your changes and push to your fork  
4. Open a Pull Request describing your changes

Please follow best practices:
- Add tests for new functionality
- Keep functions modular and documented
- Update notebook or README if you change model metadata or API

---

## 📬 Contact / Support

Author: CHVivek7  
- GitHub: https://github.com/CHVivek7  
- Email: vivekch1225@gmail.com

If you want additional features (e.g., a public API, browser extension, or CI integration), open an issue or drop an email.

---

## 🙏 Acknowledgements & Resources

- Inspired by common phishing-detection research and feature sets (anchor analysis, domain/token features)  
- Thanks to the open-source ML ecosystem: scikit-learn, Flask, pandas, numpy

---

## 📜 License

This project is licensed under the MIT License — see the full license in LICENSE.

---

Build, experiment, and keep people safe online — one URL at a time. 🚀
