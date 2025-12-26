import numpy as np
import re
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

NUM_FEATURES = 30

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify",
    "bank", "signin", "confirm", "password"
]

def extract_features(url: str):
    features = np.zeros((1, NUM_FEATURES), dtype=float)

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # -----------------
    # Lexical features
    # -----------------
    features[0, 0] = len(url)
    features[0, 1] = url.count('.')
    features[0, 2] = 1 if '@' in url else 0
    features[0, 3] = 1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url) else 0
    features[0, 4] = 1 if parsed.scheme == "https" else 0
    features[0, 5] = hostname.count('-')
    features[0, 6] = sum(c.isdigit() for c in url)
    features[0, 7] = len(path)
    features[0, 8] = hostname.count('.')
    features[0, 9] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())

    # -----------------
    # HTML / content features
    # -----------------
    try:
        response = requests.get(url, timeout=5)
        html = response.text
        soup = BeautifulSoup(html, "html.parser")

        # 10. Page fetch success
        features[0, 10] = 1

        links = soup.find_all("a", href=True)
        total_links = len(links)

        # 11. Number of anchor links
        features[0, 11] = total_links

        # 12. External link ratio
        external_links = [
            a for a in links
            if urlparse(a["href"]).hostname
            and urlparse(a["href"]).hostname != hostname
        ]
        features[0, 12] = (
            len(external_links) / total_links if total_links > 0 else 0
        )

        # 13. Presence of form tag
        features[0, 13] = 1 if soup.find("form") else 0

        # 14. Presence of iframe
        features[0, 14] = 1 if soup.find("iframe") else 0

        # 15. JavaScript redirects
        features[0, 15] = 1 if "window.location" in html.lower() else 0

        # 16. OnMouseOver usage
        features[0, 16] = 1 if "onmouseover" in html.lower() else 0

    except Exception:
        # page not reachable → leave defaults
        pass

    # Remaining features [17–29] stay neutral for now

    return features
