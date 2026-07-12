"""
Heuristic pre-screening checks for phishing URL detection.

These checks supplement the XGBoost ML model by catching patterns that
the UCI Phishing Websites Dataset's 30 features cannot capture:
  - Gibberish / high-entropy domain names
  - Known-malicious proxy domains and suspicious TLDs
  - Brand impersonation hidden in URL paths
  - Suspicious file extensions
  - URL shortener boosting

Each check returns a score from 0.0 (no signal) to 1.0 (strong phishing).
The combined heuristic score is merged with the ML probability using:
    final = 1 - (1 - ml_prob) * (1 - heuristic_prob)
"""

import math
import re
from urllib.parse import urlparse

# ------------------------------------------------------------------ constants

# Tor / anonymising proxies — subdomain is always random gibberish
TOR_PROXY_DOMAINS = [
    "tor2web.org", "onion.to", "onion.ly", "onion.cab",
    "onion.city", "onion.direct", "onion.link", "onion.ws",
]

# Free / commonly-abused TLDs (high phishing prevalence)
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",          # Freenom free TLDs
    ".xyz", ".top", ".buzz", ".click", ".link",  # cheap/abused gTLDs
    ".pro", ".info", ".gd", ".to",               # often seen in phishing
    ".cam", ".icu", ".rest", ".monster",
}

# Well-known brands that are frequently impersonated in URL paths
IMPERSONATED_BRANDS = [
    "paypal.com", "paypal.co", "microsoft.com", "apple.com",
    "amazon.com", "netflix.com", "facebook.com", "instagram.com",
    "google.com", "itau.com", "bradesco.com", "bancodobrasil.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com",
    "linkedin.com", "dropbox.com", "icloud.com", "outlook.com",
    "live.com", "signin", "login", "secure", "verify", "update",
    "account", "confirm", "webscr",
]

# Shortening services (mirrors the list in feature_extractor but used for boost)
SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly",
    "t.co", "tinyurl.com", "tr.im", "is.gd", "cli.gs", "migre.me",
    "tiny.cc", "url4.eu", "su.pr", "snipurl.com", "short.to",
    "budurl.com", "ping.fm", "post.ly", "just.as", "bkite.com",
    "snipr.com", "fic.kr", "loopt.us", "doiop.com", "short.ie",
    "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do",
    "lnkd.in", "db.tt", "qr.ae", "adf.ly", "cutt.ly", "rb.gy",
]

# Suspicious file extensions in URL paths
SUSPICIOUS_EXTENSIONS = {
    ".sh", ".exe", ".bat", ".ps1", ".cmd", ".vbs",
    ".msi", ".scr", ".pif", ".com", ".jar", ".cpl",
}


# ----------------------------------------------------------- scoring helpers

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _extract_domain_label(hostname: str) -> str:
    """Extract the main registrable label from a hostname.
    e.g. 'zjfq4lnfbs7pncr5.tor2web.org' → 'zjfq4lnfbs7pncr5'
         'www.google.com' → 'google'
    """
    parts = hostname.split(".")
    # Remove common prefixes
    while parts and parts[0] in ("www", "www2", "web", "mail", "m"):
        parts = parts[1:]
    if len(parts) >= 2:
        # Return the part before TLD/domain suffix
        return parts[0]
    return hostname


# -------------------------------------------------------------- check funcs

def _check_domain_entropy(hostname: str) -> float:
    """High entropy in domain label → likely gibberish / auto-generated.
    Legit domains: google(2.25), youtube(2.75), amazon(2.58)
    Phishing:      zjfq4lnfbs7pncr5(3.75), jhomitevd2abj3fk(3.62)
    """
    label = _extract_domain_label(hostname)
    if len(label) <= 3:
        return 0.0  # too short to judge

    entropy = _shannon_entropy(label)

    # Also check digit ratio — gibberish domains have lots of mixed digits
    digit_ratio = sum(1 for c in label if c.isdigit()) / len(label)

    score = 0.0

    # High entropy threshold (conservative)
    if entropy >= 3.5 and len(label) >= 10:
        score = 0.85
    elif entropy >= 3.2 and len(label) >= 8:
        score = 0.6
    elif entropy >= 3.0 and digit_ratio >= 0.3:
        score = 0.5
    elif entropy >= 2.5 and digit_ratio >= 0.4 and len(label) >= 5:
        # Short gibberish with heavy digit mixing (e.g. mcb0187)
        score = 0.45

    return score


def _check_tor_proxy(hostname: str) -> float:
    """Direct match against known Tor/anonymising proxy domains."""
    hn = hostname.lower()
    for proxy in TOR_PROXY_DOMAINS:
        if hn.endswith("." + proxy) or hn == proxy:
            return 0.95
    return 0.0


def _check_suspicious_tld(hostname: str) -> float:
    """Check if the TLD is commonly associated with phishing."""
    hn = hostname.lower()
    for tld in SUSPICIOUS_TLDS:
        if hn.endswith(tld):
            return 0.4  # moderate signal — many legit sites use these TLDs too
    return 0.0


def _check_brand_in_path(url: str, hostname: str) -> float:
    """Detect well-known brand domains/keywords embedded in the URL path.
    e.g.  regaranch.info/grafika/file/2012/atualizacao/www.itau.com.br/
    """
    parsed = urlparse(url)
    path = (parsed.path + "?" + parsed.query).lower()
    hn = hostname.lower()

    matches = 0
    has_full_domain_in_path = False
    for brand in IMPERSONATED_BRANDS:
        # Only flag if the brand is in the PATH, not in the actual hostname
        if brand in path and brand not in hn:
            matches += 1

    # Check for full domain patterns in path (e.g. www.itau.com.br)
    if re.search(r"www\.[a-z0-9-]+\.[a-z]{2,}", path):
        has_full_domain_in_path = True
        matches += 1

    if has_full_domain_in_path and matches >= 2:
        return 0.9  # full fake domain in path is very suspicious
    elif matches >= 3:
        return 0.9
    elif matches >= 2:
        return 0.7
    elif matches >= 1:
        return 0.5
    return 0.0


def _check_suspicious_extension(url: str) -> float:
    """Flag URLs ending in suspicious executable/script extensions."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    for ext in SUSPICIOUS_EXTENSIONS:
        if path.endswith(ext):
            return 0.7
    return 0.0


def _check_shortener(hostname: str) -> float:
    """Boost phishing score for URL shorteners — hidden destinations are
    inherently suspicious and the ML model underweights this."""
    hn = hostname.lower()
    for svc in SHORTENING_SERVICES:
        if svc in hn:
            return 0.85
    return 0.0


def _check_ip_with_port(url: str) -> float:
    """Flag raw IP addresses, especially with non-standard ports."""
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    port = parsed.port

    # Check for IP address
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        if port and port not in (80, 443):
            return 0.85  # IP + weird port = very suspicious
        return 0.5       # IP alone is suspicious
    return 0.0


def _check_path_randomness(url: str) -> float:
    """Flag URLs with long random-looking path segments (numeric/hex sequences)."""
    parsed = urlparse(url)
    path = parsed.path

    # Check for long sequences of digits or hex characters in path segments
    segments = path.split("/")
    for seg in segments:
        if len(seg) >= 10:
            digit_ratio = sum(1 for c in seg if c.isdigit()) / len(seg)
            if digit_ratio >= 0.7:
                return 0.55  # long numeric path segment
            entropy = _shannon_entropy(seg.lower())
            if entropy >= 3.5:
                return 0.45  # high entropy path segment
    return 0.0


# --------------------------------------------------------- main entry point

def heuristic_score(url: str) -> dict:
    """Run all heuristic checks and return individual scores + combined score.

    Returns:
        dict with keys:
            - 'score': combined heuristic phishing probability (0.0 to 1.0)
            - 'triggers': list of (check_name, score) for non-zero checks
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    checks = [
        ("domain_entropy",      _check_domain_entropy(hostname)),
        ("tor_proxy",           _check_tor_proxy(hostname)),
        ("suspicious_tld",      _check_suspicious_tld(hostname)),
        ("brand_in_path",       _check_brand_in_path(url, hostname)),
        ("suspicious_extension", _check_suspicious_extension(url)),
        ("shortener",           _check_shortener(hostname)),
        ("ip_with_port",        _check_ip_with_port(url)),
        ("path_randomness",     _check_path_randomness(url)),
    ]

    triggers = [(name, s) for name, s in checks if s > 0]

    # Combine all non-zero scores: 1 - ∏(1 - s_i)
    # This means any single strong signal can flag the URL.
    combined = 0.0
    if triggers:
        product = 1.0
        for _, s in triggers:
            product *= (1 - s)
        combined = 1 - product

    return {
        "score": combined,
        "triggers": triggers,
    }
