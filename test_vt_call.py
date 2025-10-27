import os
import json

# Try to load utils/.env manually if present (simple KEY=VALUE parser)
env_path = os.path.join(os.path.dirname(__file__), 'utils', '.env')
if os.path.exists(env_path):
    try:
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip())
    except Exception:
        pass

from utils.threat_intel import check_url_virustotal

key = os.getenv('VIRUSTOTAL_API_KEY')
if not key:
    print('<<MISSING>>')
else:
    print('VIRUSTOTAL_API_KEY is set (hidden). Running test query...')
    res = check_url_virustotal('http://example.com')
    print('<<RESULT>>')
    print(json.dumps(res, indent=2))
