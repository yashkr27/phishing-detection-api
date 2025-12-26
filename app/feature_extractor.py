import numpy as np
import re
from urllib.parse import urlparse

NUM_FEATURES = 30  # keep EXACT as trained

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "account", "update", "verify",
    "bank", "signin", "confirm", "password"
]

def extract_features(url: str):
    features = np.zeros((1, NUM_FEATURES), dtype=float)

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # --- Existing lexical features ---
    features[0, 0] = len(url)                 # URL length
    features[0, 1] = url.count('.')            # dot count
    features[0, 2] = 1 if '@' in url else 0    # '@' presence

    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    features[0, 3] = 1 if re.search(ip_pattern, url) else 0  # IP in URL

    features[0, 4] = 1 if parsed.scheme == "https" else 0    # HTTPS

    # --- New lexical / structural features ---
    features[0, 5] = hostname.count('-')       # hyphens in domain
    features[0, 6] = sum(c.isdigit() for c in url)  # digit count
    features[0, 7] = len(path)                 # path length
    features[0, 8] = hostname.count('.')       # subdomain count

    # Suspicious keyword presence
    features[0, 9] = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())

    return features
