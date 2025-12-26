import numpy as np
import re
import requests
import socket
from urllib.parse import urlparse
from bs4 import BeautifulSoup

NUM_FEATURES = 30

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify",
    "bank", "signin", "confirm", "password"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

def extract_features(url: str):
    features = np.zeros((1, NUM_FEATURES), dtype=float)

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # --------------------
    # Lexical features
    # --------------------
    features[0, 0] = len(url)
    features[0, 1] = url.count('.')
    features[0, 2] = int('@' in url)
    features[0, 3] = int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url)))
    features[0, 4] = int(parsed.scheme == "https")
    features[0, 5] = hostname.count('-')
    features[0, 6] = sum(c.isdigit() for c in url)
    features[0, 7] = len(path)
    features[0, 8] = hostname.count('.')
    features[0, 9] = sum(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS)

    # --------------------
    # HTML-based features (SAFE)
    # --------------------
    try:
        response = requests.get(url, timeout=3, headers=HEADERS)
        if response.status_code != 200:
            raise Exception()

        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        features[0, 10] = 1

        links = soup.find_all("a", href=True)
        total_links = len(links)
        features[0, 11] = total_links

        external_links = [
            a for a in links
            if urlparse(a["href"]).hostname
            and urlparse(a["href"]).hostname != hostname
        ]
        features[0, 12] = len(external_links) / total_links if total_links else 0

        features[0, 13] = int(bool(soup.find("form")))
        features[0, 14] = int(bool(soup.find("iframe")))
        features[0, 15] = int("window.location" in html.lower())
        features[0, 16] = int("onmouseover" in html.lower())

    except Exception:
        pass  # defaults remain 0

    # --------------------
    # Domain features
    # --------------------
    features[0, 17] = len(hostname)
    features[0, 18] = hostname.count('.')

    shorteners = ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]
    features[0, 19] = int(any(s in url.lower() for s in shorteners))

    suspicious_tlds = [".zip", ".review", ".country", ".kim", ".cricket", ".work"]
    features[0, 20] = int(any(hostname.endswith(tld) for tld in suspicious_tlds))

    try:
        socket.gethostbyname(hostname)
        features[0, 21] = 1
    except Exception:
        features[0, 21] = 0

    # --------------------
    # Reputation placeholders (documented)
    # --------------------
    for i in range(22, 30):
        features[0, i] = 0

    return features
