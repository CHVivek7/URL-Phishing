import importlib.util, pathlib, sys
root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('app', str(root / 'app.py'))
mod = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(root))
spec.loader.exec_module(mod)

upi = 'upi://pay?pa=amazon-refund@paytm&pn=Amazon%20Support&am=1.00&cu=INR'
parsed = mod.parse_upi_uri(upi)
print('parsed_upi=', parsed)
trusted = parsed.get('pa') in mod.app.config.get('UPI_TRUSTED_PA', [])
print('trusted=', trusted)
print('is_upi_brand_spoof=', mod.is_upi_brand_spoof(parsed))
print('assess_upi_risk=', mod.assess_upi_risk(parsed, trusted))
