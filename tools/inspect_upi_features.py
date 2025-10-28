import importlib.util, pathlib, sys
root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('app', str(root / 'app.py'))
mod = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(root))
spec.loader.exec_module(mod)

upi = 'upi://pay?pa=netflix-renewal@oksbi&pn=Subscription%20Renewal&am=799.00&cu=INR'
parsed = mod.parse_upi_uri(upi)
print('parsed_upi=', parsed)
trusted = parsed.get('pa') in mod.app.config.get('UPI_TRUSTED_PA', [])
print('trusted=', trusted)
model = mod.app.config.get('UPI_MODEL')
# replicate features order
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
features.append(1 if trusted else 0)
print('feature_vector=', features)
import numpy as _np
X = _np.array([features])
if model is not None:
    try:
        print('model predict_proba=', model.predict_proba(X))
        print('model predict=', model.predict(X))
    except Exception as e:
        print('model error:', e)
else:
    print('No model loaded; using heuristics')
    print('assess_upi_risk=', mod.assess_upi_risk(parsed, trusted))
