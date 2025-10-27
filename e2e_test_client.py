from app import app
import re

with app.test_client() as client:
    resp = client.post('/', data={'url': 'http://faceb%6F%6Fk.com'}, follow_redirects=True)
    html = resp.get_data(as_text=True)
    m = re.search(r'<pre[^>]*class="darkweb-report"[^>]*>(.*?)</pre>', html, re.S | re.I)
    if m:
        content = m.group(1)
        # Strip HTML entities or tags remaining
        text = re.sub(r'<[^>]+>', '', content)
        print(text.strip())
    else:
        # fallback: print the whole body text
        body = re.sub(r'<[^>]+>', '', html)
        print(body.strip())
