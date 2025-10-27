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
# Test the problematic URL with repeated 'w's
resp = client.post('/', data={'url': 'http://wwww.example.com'})
print('STATUS:', resp.status_code)
html = resp.data.decode('utf-8')
start = html.find('Legitimate:')
if start == -1:
    start = html.find('Phishing Detection')
end = start + 1200
print(html[start:end])
