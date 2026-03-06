"""
Feature extractor aligned with UCI Phishing Websites Dataset.

Produces exactly 30 features in the same order and encoding (-1 / 0 / 1)
that the XGBoost model was trained on.

Reference: Mohammad, Thabtah & McCluskey (2014)
           https://archive.ics.uci.edu/dataset/327/phishing+websites
"""

import re
import ssl
import socket
import numpy as np
import requests
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup

try:
    import whois as python_whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

NUM_FEATURES = 30

# ------------------------------------------------------------------ helpers
SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "shorte.st", "go2l.ink", "x.co", "ow.ly",
    "t.co", "tinyurl.com", "tr.im", "is.gd", "cli.gs", "yfrog.com",
    "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr",
    "twurl.nl", "snipurl.com", "short.to", "budurl.com", "ping.fm",
    "post.ly", "just.as", "bkite.com", "snipr.com", "fic.kr",
    "loopt.us", "doiop.com", "short.ie", "kl.am", "wp.me", "rubyurl.com",
    "om.ly", "to.ly", "bit.do", "lnkd.in", "db.tt", "qr.ae",
    "adf.ly", "cutt.ly", "rb.gy",
]

PREFERRED_PORTS = [21, 22, 23, 80, 443, 8080]

# WHOIS cache to avoid repeated lookups for the same domain in one request
_whois_cache: dict = {}


def _get_whois(hostname: str):
    """Cached WHOIS lookup. Returns whois object or None."""
    if not _WHOIS_AVAILABLE or not hostname:
        return None
    if hostname in _whois_cache:
        return _whois_cache[hostname]
    try:
        w = python_whois.whois(hostname)
        _whois_cache[hostname] = w
        return w
    except Exception:
        _whois_cache[hostname] = None
        return None


def _fetch_page(url: str, timeout: float = 2.0):
    """Fetch HTML and count redirects. Returns (html, soup, hostname, redirect_count) or Nones."""
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
            allow_redirects=True,
        )
        if resp.status_code != 200:
            return None, None, None, len(resp.history)
        soup = BeautifulSoup(resp.text, "html.parser")
        return resp.text, soup, urlparse(resp.url).hostname, len(resp.history)
    except Exception:
        return None, None, None, 0


def _is_external(href: str, page_hostname: str) -> bool:
    """True when *href* points to a different domain than *page_hostname*."""
    try:
        h = urlparse(href).hostname
        return h is not None and h != page_hostname
    except Exception:
        return False


# ------------------------------------------------- individual feature funcs

def _having_ip_address(url: str) -> int:
    """Feature 0: -1 if URL contains an IP address, else 1."""
    if re.search(r"(\d{1,3}\.){3}\d{1,3}", url):
        return -1
    # Hex / octal IP patterns
    if re.search(r"0x[0-9a-fA-F]{1,2}\.", url):
        return -1
    return 1


def _url_length(url: str) -> int:
    """Feature 1: 1 if len<54, 0 if 54-75, -1 if >75."""
    length = len(url)
    if length < 54:
        return 1
    if length <= 75:
        return 0
    return -1


def _shortening_service(url: str) -> int:
    """Feature 2: -1 if URL uses a shortening service, else 1."""
    domain = urlparse(url).netloc.lower()
    for svc in SHORTENING_SERVICES:
        if svc in domain:
            return -1
    return 1


def _having_at_symbol(url: str) -> int:
    """Feature 3: -1 if @ in URL, else 1."""
    return -1 if "@" in url else 1


def _double_slash_redirecting(url: str) -> int:
    """Feature 4: -1 if // appears after the protocol portion, else 1."""
    # Find position after the initial protocol://
    after_protocol = url.find("//")
    if after_protocol >= 0:
        rest = url[after_protocol + 2:]
        if "//" in rest:
            return -1
    return 1


def _prefix_suffix(hostname: str) -> int:
    """Feature 5: -1 if '-' in domain name, else 1."""
    return -1 if "-" in hostname else 1


def _having_sub_domain(hostname: str) -> int:
    """Feature 6: count dots in hostname (excluding TLD).
    1 dot → 1 (legitimate), 2 dots → 0 (suspicious), 3+ → -1 (phishing)."""
    dot_count = hostname.count(".")
    if dot_count <= 1:
        return 1
    if dot_count == 2:
        return 0
    return -1


def _ssl_final_state(url: str, hostname: str) -> int:
    """Feature 7: 1 if valid HTTPS cert, 0 if HTTPS but untrusted, -1 if no HTTPS."""
    if urlparse(url).scheme != "https":
        return -1
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(2)
            s.connect((hostname, 443))
        return 1
    except ssl.SSLCertVerificationError:
        return 0
    except Exception:
        return -1


def _domain_registration_length(hostname: str) -> int:
    """Feature 8: -1 if registration period ≤ 1 year, else 1."""
    w = _get_whois(hostname)
    if w is None:
        return 0
    try:
        exp = w.expiration_date
        cre = w.creation_date
        if isinstance(exp, list): exp = exp[0]
        if isinstance(cre, list): cre = cre[0]
        if exp and cre:
            reg_length = (exp - cre).days
            return 1 if reg_length >= 365 else -1
    except Exception:
        pass
    return 0


def _favicon(soup, page_hostname: str) -> int:
    """Feature 9: -1 if favicon from external domain, else 1."""
    if soup is None:
        return 1
    for link in soup.find_all("link", rel=True):
        rels = [r.lower() for r in link["rel"]]
        if "icon" in rels or "shortcut" in rels:
            href = link.get("href", "")
            if _is_external(href, page_hostname):
                return -1
    return 1


def _port(url: str) -> int:
    """Feature 10: -1 if non-standard port, else 1."""
    parsed = urlparse(url)
    port = parsed.port
    if port is None:
        return 1
    return 1 if port in PREFERRED_PORTS else -1


def _https_token(hostname: str) -> int:
    """Feature 11: -1 if 'https' appears in the domain part (deceptive), else 1."""
    return -1 if "https" in hostname.lower() else 1


def _request_url(soup, page_hostname: str) -> int:
    """Feature 12: ratio of external objects (img, script, link, audio, video, embed).
    <22% → 1, 22-61% → 0, >61% → -1."""
    if soup is None:
        return 0
    tags = soup.find_all(["img", "script", "link", "audio", "video", "embed", "source"], src=True)
    total = len(tags)
    if total == 0:
        return 1
    external = sum(1 for t in tags if _is_external(t.get("src", ""), page_hostname))
    ratio = external / total
    if ratio < 0.22:
        return 1
    if ratio <= 0.61:
        return 0
    return -1


def _url_of_anchor(soup, page_hostname: str) -> int:
    """Feature 13: ratio of anchor hrefs pointing externally or to '#'/empty.
    <31% → 1, 31-67% → 0, >67% → -1."""
    if soup is None:
        return 0
    anchors = soup.find_all("a", href=True)
    total = len(anchors)
    if total == 0:
        return 1
    suspicious = 0
    for a in anchors:
        href = a["href"].strip()
        if href in ("#", "", "javascript:void(0)") or href.startswith("javascript:"):
            suspicious += 1
        elif _is_external(href, page_hostname):
            suspicious += 1
    ratio = suspicious / total
    if ratio < 0.31:
        return 1
    if ratio <= 0.67:
        return 0
    return -1


def _links_in_tags(soup, page_hostname: str) -> int:
    """Feature 14: ratio of external URLs in <meta>, <script>, <link> tags.
    <17% → 1, 17-81% → 0, >81% → -1."""
    if soup is None:
        return 0
    tags = soup.find_all(["meta", "script", "link"])
    total = len(tags)
    if total == 0:
        return 1
    external = 0
    for tag in tags:
        for attr in ("href", "src", "content"):
            val = tag.get(attr, "")
            if val and _is_external(val, page_hostname):
                external += 1
                break
    ratio = external / total
    if ratio < 0.17:
        return 1
    if ratio <= 0.81:
        return 0
    return -1


def _sfh(soup, page_hostname: str) -> int:
    """Feature 15: Server Form Handler.
    -1 if blank/about:blank, 0 if foreign domain, 1 if same domain."""
    if soup is None:
        return 0
    form = soup.find("form")
    if form is None:
        return 1
    action = (form.get("action") or "").strip()
    if action in ("", "about:blank"):
        return -1
    if _is_external(action, page_hostname):
        return 0
    return 1


def _submitting_to_email(soup) -> int:
    """Feature 16: -1 if form action uses 'mailto:', else 1."""
    if soup is None:
        return 1
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip().lower()
        if "mailto:" in action or "mail(" in action:
            return -1
    return 1


def _abnormal_url(url: str, hostname: str) -> int:
    """Feature 17: -1 if WHOIS registrant domain doesn't match URL hostname."""
    w = _get_whois(hostname)
    if w is None:
        return 0
    try:
        registrar = (w.domain_name or "")
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else ""
        registrar = registrar.lower()
        if registrar and registrar in hostname.lower():
            return 1
        return -1
    except Exception:
        return 0


def _redirect(redirect_count: int) -> int:
    """Feature 18: 1 if ≤1 redirect, 0 if 2-3, -1 if ≥4."""
    if redirect_count <= 1:
        return 1
    if redirect_count <= 3:
        return 0
    return -1


def _on_mouseover(html: str) -> int:
    """Feature 19: -1 if onmouseover changes status bar, else 1."""
    if html is None:
        return 1
    lower = html.lower()
    if "onmouseover" in lower and "window.status" in lower:
        return -1
    return 1


def _right_click(html: str) -> int:
    """Feature 20: -1 if right-click disabled, else 1."""
    if html is None:
        return 1
    lower = html.lower()
    if "event.button==2" in lower or "event.button == 2" in lower or "contextmenu" in lower:
        return -1
    return 1


def _popup_window(html: str) -> int:
    """Feature 21: -1 if popup contains text input, else 1."""
    if html is None:
        return 1
    lower = html.lower()
    if "window.open" in lower and ("prompt(" in lower or "<input" in lower):
        return -1
    return 1


def _iframe(soup) -> int:
    """Feature 22: -1 if iframe or frameBorder present, else 1."""
    if soup is None:
        return 1
    if soup.find("iframe") or soup.find("frame"):
        return -1
    return 1


def _age_of_domain(hostname: str) -> int:
    """Feature 23: -1 if domain age < 6 months, else 1."""
    w = _get_whois(hostname)
    if w is None:
        return 0
    try:
        creation = w.creation_date
        if isinstance(creation, list): creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            return 1 if age_days >= 180 else -1
    except Exception:
        pass
    return 0


def _dns_record(hostname: str) -> int:
    """Feature 24: -1 if no DNS record, else 1."""
    try:
        socket.gethostbyname(hostname)
        return 1
    except Exception:
        return -1


def _web_traffic() -> int:
    """Feature 25: Alexa deprecated — default 0."""
    return 0


def _page_rank() -> int:
    """Feature 26: Google PageRank deprecated — default 0."""
    return 0


def _google_index() -> int:
    """Feature 27: Requires Google API — default 0."""
    return 0


def _links_pointing_to_page() -> int:
    """Feature 28: Requires external data — default 0."""
    return 0


def _statistical_report() -> int:
    """Feature 29: Requires PhishTank API — default 0."""
    return 0


# -------------------------------------------------------- main entry point

def extract_features(url: str):
    """Return a (1, 30) numpy array of features matching the UCI Phishing
    Websites Dataset encoding (-1 / 0 / 1)."""

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    # Fetch page HTML (always, not gated behind keyword matching)
    html, soup, page_hostname, redirect_count = _fetch_page(url)
    if page_hostname is None:
        page_hostname = hostname

    features = np.zeros((1, NUM_FEATURES), dtype=float)

    # Clear WHOIS cache for fresh request
    _whois_cache.clear()

    # Address-bar based features (0-7)
    features[0, 0]  = _having_ip_address(url)
    features[0, 1]  = _url_length(url)
    features[0, 2]  = _shortening_service(url)
    features[0, 3]  = _having_at_symbol(url)
    features[0, 4]  = _double_slash_redirecting(url)
    features[0, 5]  = _prefix_suffix(hostname)
    features[0, 6]  = _having_sub_domain(hostname)
    features[0, 7]  = _ssl_final_state(url, hostname)

    # Domain-based features (8-9)
    features[0, 8]  = _domain_registration_length(hostname)
    features[0, 9]  = _favicon(soup, page_hostname)

    # Abnormality-based features (10-14)
    features[0, 10] = _port(url)
    features[0, 11] = _https_token(hostname)
    features[0, 12] = _request_url(soup, page_hostname)
    features[0, 13] = _url_of_anchor(soup, page_hostname)
    features[0, 14] = _links_in_tags(soup, page_hostname)

    # HTML/JS-based features (15-22)
    features[0, 15] = _sfh(soup, page_hostname)
    features[0, 16] = _submitting_to_email(soup)
    features[0, 17] = _abnormal_url(url, hostname)
    features[0, 18] = _redirect(redirect_count)
    features[0, 19] = _on_mouseover(html)
    features[0, 20] = _right_click(html)
    features[0, 21] = _popup_window(html)
    features[0, 22] = _iframe(soup)

    # Domain-based features (23-24)
    features[0, 23] = _age_of_domain(hostname)
    features[0, 24] = _dns_record(hostname)

    # Reputation features (25-29) — external APIs unavailable
    features[0, 25] = _web_traffic()
    features[0, 26] = _page_rank()
    features[0, 27] = _google_index()
    features[0, 28] = _links_pointing_to_page()
    features[0, 29] = _statistical_report()

    return features