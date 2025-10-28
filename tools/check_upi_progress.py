import importlib.util, pathlib, sys
root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('app', str(root / 'app.py'))
mod = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(root))
spec.loader.exec_module(mod)
client = mod.app.test_client()
upi = 'upi://pay?pa=netflix-renewal@oksbi&pn=Subscription%20Renewal&am=799.00&cu=INR'
resp = client.post('/', data={'url': upi})
html = resp.data.decode('utf-8')
print('Has progress-bar?', 'progress-bar' in html)
start = html.find('<div class="progress"')
if start!=-1:
    print(html[start:start+500])
else:
    print('No progress div found')
