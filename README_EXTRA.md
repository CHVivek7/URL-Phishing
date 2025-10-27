New features in this branch:

- QR Code URL extraction: Upload or capture QR images via the web UI. Server-side decoding uses Pillow + pyzbar. The web UI also supports camera capture and in-browser QR scanning.
- URL unshortening: Short links are resolved before analysis so the classifier and threat intel examine the true final destination.
- Threat Intelligence: Optional VirusTotal v3 integration. If you set the environment variable `VIRUSTOTAL_API_KEY`, the app will query VirusTotal for a URL report and compute a danger score (1-10) plus an estimated impact (positives/total).

To enable VirusTotal checks (optional):

# Windows PowerShell example
$env:VIRUSTOTAL_API_KEY = "<your-api-key>"
python app.py

If the API key is not set, the app will still perform ML-based phishing detection and QR/unshorten features but will skip threat intelligence queries.
