"""
Feature Extractor for Phishing URL Detection
Extracts 15 features from a URL without visiting it.
"""

import re
import math
import tldextract
from urllib.parse import urlparse

# ─────────────────────────────────────────────
# KNOWN DATA
# ─────────────────────────────────────────────

TRUSTED_DOMAINS = {
    "google", "youtube", "facebook", "amazon", "microsoft",
    "apple", "twitter", "instagram", "linkedin", "github",
    "netflix", "wikipedia", "yahoo", "reddit", "whatsapp",
    "sbi", "hdfcbank", "icicibank", "paytm", "irctc",
    "incometax", "uidai", "digitalindia", "gov"
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update",
    "banking", "password", "confirm", "click", "free", "lucky",
    "winner", "prize", "urgent", "alert", "suspended", "limited",
    "unusual", "activity", "verify", "validate", "credential"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".click", ".link", ".download", ".zip", ".review"
}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def entropy(s: str) -> float:
    """Shannon entropy — high entropy = random-looking = suspicious."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

# ─────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────

def extract_features(url: str) -> dict:
    """
    Extract 15 features from a URL.
    Returns a dict with feature names and values.
    """
    url = url.strip()

    # Make sure URL has a scheme for parsing
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed  = urlparse(url)
    ext     = tldextract.extract(url)
    domain  = ext.domain.lower()
    suffix  = ext.suffix.lower()
    subdom  = ext.subdomain.lower()
    full    = parsed.netloc.lower()
    path    = parsed.path.lower()
    query   = parsed.query.lower()
    full_url = url.lower()

    features = {}

    # 1. URL length — phishing URLs tend to be longer
    features["url_length"] = len(url)

    # 2. Domain length
    features["domain_length"] = len(domain)

    # 3. Number of dots in full URL — more dots = more subdomains = suspicious
    features["dot_count"] = full_url.count(".")

    # 4. Number of hyphens — attackers use g-o-o-g-l-e.com style tricks
    features["hyphen_count"] = full.count("-")

    # 5. Uses HTTPS? (0 = HTTP = bad, 1 = HTTPS)
    features["is_https"] = 1 if parsed.scheme == "https" else 0

    # 6. Has IP address instead of domain? e.g. http://192.168.1.1/login
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    features["has_ip"] = 1 if ip_pattern.match(full.split(":")[0]) else 0

    # 7. Number of subdomains — legit sites rarely have 3+ subdomains
    features["subdomain_count"] = len([s for s in subdom.split(".") if s]) if subdom else 0

    # 8. Suspicious TLD?
    features["suspicious_tld"] = 1 if f".{suffix}" in SUSPICIOUS_TLDS else 0

    # 9. Count of phishing keywords in full URL
    features["phishing_keywords"] = sum(1 for kw in PHISHING_KEYWORDS if kw in full_url)

    # 10. Has @ symbol? http://legit.com@evil.com — browser goes to evil.com
    features["has_at_symbol"] = 1 if "@" in full_url else 0

    # 11. Has double slash in path? (//) — redirection trick
    features["has_double_slash"] = 1 if "//" in path else 0

    # 12. Number of special characters (%, =, &, ?)
    features["special_char_count"] = sum(full_url.count(c) for c in ["%", "=", "&", "?", "~"])

    # 13. Domain entropy — random-looking domains are suspicious
    features["domain_entropy"] = round(entropy(domain), 4)

    # 14. Domain looks like a known brand with extra chars?
    #     e.g. "paypa1", "g00gle", "arnazon"
    brand_spoofed = 0
    for brand in TRUSTED_DOMAINS:
        if brand in domain and domain != brand:
            brand_spoofed = 1
            break
    features["brand_in_domain"] = brand_spoofed

    # 15. Path length
    features["path_length"] = len(path)

    return features


def features_to_vector(features: dict) -> list:
    """Convert features dict to ordered list for ML model."""
    ORDER = [
        "url_length", "domain_length", "dot_count", "hyphen_count",
        "is_https", "has_ip", "subdomain_count", "suspicious_tld",
        "phishing_keywords", "has_at_symbol", "has_double_slash",
        "special_char_count", "domain_entropy", "brand_in_domain",
        "path_length"
    ]
    return [features[k] for k in ORDER]


def explain_features(features: dict) -> list:
    """Return human-readable explanation of each suspicious feature."""
    flags = []

    if features["url_length"] > 75:
        flags.append(("WARN", f"URL is very long ({features['url_length']} chars) — common in phishing"))
    if features["is_https"] == 0:
        flags.append(("HIGH", "Uses HTTP not HTTPS — no encryption, easy to spoof"))
    if features["has_ip"] == 1:
        flags.append(("HIGH", "IP address used instead of domain name — classic phishing sign"))
    if features["hyphen_count"] >= 2:
        flags.append(("WARN", f"{features['hyphen_count']} hyphens in domain — e.g. secure-login-google.com"))
    if features["subdomain_count"] >= 3:
        flags.append(("WARN", f"{features['subdomain_count']} subdomains — e.g. login.verify.google.evil.com"))
    if features["suspicious_tld"] == 1:
        flags.append(("HIGH", "Suspicious TLD (.xyz, .tk, .ml etc.) — free domains used by attackers"))
    if features["phishing_keywords"] >= 2:
        flags.append(("HIGH", f"{features['phishing_keywords']} phishing keywords found (login, verify, secure, etc.)"))
    if features["has_at_symbol"] == 1:
        flags.append(("HIGH", "@ symbol in URL — browser ignores everything before @"))
    if features["has_double_slash"] == 1:
        flags.append(("WARN", "Double slash in path — possible open redirect"))
    if features["domain_entropy"] > 3.5:
        flags.append(("WARN", f"High domain entropy ({features['domain_entropy']}) — random-looking domain"))
    if features["brand_in_domain"] == 1:
        flags.append(("HIGH", "Known brand name found inside domain — likely spoofing attempt"))

    return flags


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    test_urls = [
        "https://google.com/search?q=hello",
        "http://secure-login-paypal-verify.xyz/account/confirm?user=you",
        "https://github.com/login",
        "http://192.168.1.1/admin/login.php",
        "https://accounts.google.com.verify-login.tk/signin",
    ]

    for url in test_urls:
        print(f"\nURL: {url}")
        feats = extract_features(url)
        print(f"Features: {feats}")
        flags = explain_features(feats)
        print(f"Flags: {flags}")