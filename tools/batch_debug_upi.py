"""Batch diagnostic for UPI URIs.

Usage:
  - Place UPI URIs (one per line) in tools/upi_samples.txt and run:
      python tools/batch_debug_upi.py
  - Or pass UPI URIs as command-line args:
      python tools/batch_debug_upi.py "upi://pay?pa=..." "upi://pay?pa=..."

Output: For each UPI prints:
  - parsed_upi
  - is_upi_brand_spoof
  - assess_upi_risk output
  - model.predict_proba (if model loaded) and model.predict
  - feature vector used for model
"""
import sys
import pathlib
import importlib.util

root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('app', str(root / 'app.py'))
mod = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(root))
spec.loader.exec_module(mod)

# Collect URIs from args or from tools/upi_samples.txt
uris = []
if len(sys.argv) > 1:
    uris = sys.argv[1:]
else:
    sample_file = root / 'tools' / 'upi_samples.txt'
    if sample_file.exists():
        with open(sample_file, 'r', encoding='utf-8') as f:
            for line in f:
                u = line.strip()
                if u:
                    uris.append(u)

if not uris:
    print("No UPI URIs provided. Put them in tools/upi_samples.txt or pass as command-line args.")
    sys.exit(1)

model = mod.app.config.get('UPI_MODEL')

for i, u in enumerate(uris, 1):
    print('='*80)
    print(f"[{i}/{len(uris)}] UPI: {u}")
    parsed = mod.parse_upi_uri(u)
    print('parsed_upi=', parsed)
    try:
        brand_spoof = mod.is_upi_brand_spoof(parsed)
    except Exception as e:
        brand_spoof = f'ERROR: {e}'
    print('is_upi_brand_spoof=', brand_spoof)
    trusted = parsed.get('pa') in mod.app.config.get('UPI_TRUSTED_PA', [])
    print('trusted=', trusted)

    try:
        risk = mod.assess_upi_risk(parsed, trusted)
        print('assess_upi_risk=', risk)
    except Exception as e:
        print('assess_upi_risk error:', e)

    # If model available, show the raw feature vector and model outputs
    if model is not None:
        try:
            pa = (parsed.get('pa') or '').strip()
            pn = (parsed.get('pn') or '').strip()
            raw = ' '.join(parsed.values())
            features = []
            features.append(1 if pa else 0)
            features.append(len(pn))
            features.append(1 if '%' in raw or '+' in raw else 0)
            features.append(len([c for c in pa if not c.isalnum() and c not in ['@','_','-','.']]))
            features.append(1 if pa and pa.replace('@','').isdigit() else 0)
            features.append(1 if any(kw in pn.lower() for kw in mod.app.config.get('PHISHING_KEYWORDS', [])) else 0)
            features.append(len(raw))
            # brand_spoof as feature
            try:
                features.append(1 if mod.is_upi_brand_spoof(parsed) else 0)
            except Exception:
                features.append(0)

            import numpy as _np
            X = _np.array([features])
            print('feature_vector=', features)
            proba = model.predict_proba(X)[0]
            pred = model.predict(X)[0]
            print('model.predict_proba=', proba)
            print('model.predict=', pred)
        except Exception as e:
            print('model error:', e)

print('\nDone')
