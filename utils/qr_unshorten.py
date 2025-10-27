from PIL import Image
import io
from urllib.parse import urlparse
import requests

# Prefer OpenCV's QR detector (no external zbar DLL dependency). Fall back to pyzbar if available.
try:
    import cv2
    import numpy as np
    HAS_CV2 = True
except Exception:
    HAS_CV2 = False

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    HAS_PYZBAR = True
except Exception:
    HAS_PYZBAR = False

# Known shortener domains (can be extended)
KNOWN_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "ow.ly",
    "buff.ly", "adf.ly", "bitly.com", "shorturl.at"
}


def decode_qr_from_file(file_stream):
    """Decode QR code from an uploaded file-like object. Returns decoded string or None.

    Uses OpenCV's QRCodeDetector if available (no extra system DLLs). Falls back to pyzbar when
    OpenCV is not available.
    """
    try:
        data = file_stream.read()

        # Try OpenCV first (no zbar DLL required)
        if HAS_CV2:
            try:
                arr = np.frombuffer(data, np.uint8)
                img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                if img is None:
                    # Try via PIL then convert
                    pil = Image.open(io.BytesIO(data)).convert('RGB')
                    img = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)

                detector = cv2.QRCodeDetector()
                data_str, points, _ = detector.detectAndDecode(img)
                if data_str:
                    return data_str
            except Exception:
                # fall through to pyzbar
                pass

        # Fallback to pyzbar if installed
        if HAS_PYZBAR:
            try:
                pil_img = Image.open(io.BytesIO(data)).convert('RGB')
                decoded = pyzbar_decode(pil_img)
                if decoded:
                    return decoded[0].data.decode('utf-8')
            except Exception:
                return None

        return None
    except Exception:
        return None


def is_shortened(url):
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain in KNOWN_SHORTENERS
    except Exception:
        return False


def unshorten_url(url, timeout=5):
    """Resolve a (possibly shortened) URL to its final target.

    Uses HEAD first (faster), falls back to GET when needed. Returns the final URL
    or the original on failure.
    """
    try:
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                          '(KHTML, like Gecko) Chrome/115.0 Safari/537.36'
        }

        # Try HEAD first
        try:
            resp = session.head(url, allow_redirects=True, timeout=timeout, headers=headers)
        except Exception:
            resp = None

        # If HEAD didn't produce a redirect chain or was blocked, try GET with streaming
        if not resp or resp.status_code in (405, 400) or (hasattr(resp, 'url') and resp.url == url):
            try:
                resp = session.get(url, allow_redirects=True, timeout=timeout, headers=headers, stream=True)
                # avoid downloading body
                try:
                    resp.close()
                except Exception:
                    pass
            except Exception:
                resp = None

        if resp and hasattr(resp, 'url'):
            return resp.url
        return url
    except Exception:
        return url
