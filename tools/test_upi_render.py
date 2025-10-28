import importlib.util
import pathlib

# Load app.py as a module by file location to avoid import path issues
root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('app', str(root / 'app.py'))
mod = importlib.util.module_from_spec(spec)
import sys
sys.path.insert(0, str(root))
spec.loader.exec_module(mod)

flask_app = getattr(mod, 'app')
client = flask_app.test_client()
# Test the UPI URL
upi = 'upi://pay?pa=netflix-renewal@oksbi&pn=Subscription%20Renewal&am=799.00&cu=INR'
resp = client.post('/', data={'url': upi})
print('STATUS:', resp.status_code)
html = resp.data.decode('utf-8')
# find the Final URL block
idx = html.find('Final URL:')
if idx == -1:
    idx = html.find('🔗 Final URL')
if idx != -1:
    print(html[idx: idx+400])
else:
    # print a larger chunk to inspect
    print(html[:1000])
