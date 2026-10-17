"""
detector.py
-----------
Heuristic phishing-URL analyzer.

Idea: a phishing URL rarely has ONE obvious tell. It has several small ones.
So we extract a set of features, give each a weight, add up the weights of the
ones that fire, and map the total to a verdict. Every point is explainable,
which is the whole reason this is rules-based and not a black-box model.

Nothing here talks to the network. We only parse the string.
"""

import re
import math
from urllib.parse import urlparse

# Free / abused TLDs that show up a lot in phishing campaigns.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work",
    "zip", "mov", "country", "kim", "science", "party",
}

# Domains whose only job is to hide the real destination.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at",
}

# Words phishers put in URLs to look legitimate.
SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "secure", "account", "update",
    "confirm", "password", "bank", "webscr", "ebayisapi",
    "paypal", "wallet", "unlock", "billing", "support",
}


def _shannon_entropy(s):
    """Randomness of a string. High entropy domains often mean junk/algorithmic hosts."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _is_ip(host):
    """True if the host is a raw IPv4 address instead of a domain name."""
    return bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host or ""))


def _registered_domain(host):
    """
    Cheap 'domain.tld' guess: last two labels.
    Not public-suffix accurate (co.uk etc.), but good enough and explainable.
    """
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def analyze(raw_url):
    """
    Take a URL string, return a dict:
      { url, score, verdict, signals: [ {name, points, detail}, ... ] }
    """
    url = (raw_url or "").strip()
    if not url:
        return {"url": url, "score": 0, "verdict": "Empty", "signals": []}

    # Make sure urlparse sees a scheme so netloc is filled correctly.
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    full = url.lower()

    signals = []

    def add(name, points, detail):
        signals.append({"name": name, "points": points, "detail": detail})

    # 1. Raw IP as host — real brands use names, not 192.168-style hosts.
    if _is_ip(host):
        add("IP address as host", 30, f"Host is a raw IP: {host}")

    # 2. '@' in the URL — browsers treat everything before '@' as credentials,
    #    so the real host is what comes AFTER it. Classic redirect trick.
    if "@" in url:
        add("'@' in URL", 25, "Everything before '@' is ignored by the browser")

    # 3. Punycode — used for homograph attacks (paypaI vs paypal with lookalikes).
    if "xn--" in host:
        add("Punycode host", 25, "xn-- prefix can hide lookalike characters")

    # 4. No HTTPS.
    if parsed.scheme == "http":
        add("No HTTPS", 10, "Traffic is not encrypted")

    # 5. Suspicious TLD.
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        add("Suspicious TLD", 15, f".{tld} is frequently abused")

    # 6. URL shortener — hides the true destination.
    if _registered_domain(host) in SHORTENERS:
        add("URL shortener", 15, f"{host} hides the real target")

    # 7. Too many subdomains — login.secure.account.example.com style padding.
    dots = host.count(".")
    if dots >= 4:
        add("Many subdomains", 15, f"{dots} dots in host")
    elif dots == 3:
        add("Several subdomains", 8, f"{dots} dots in host")

    # 8. Hyphens in the domain (brand-login.com).
    hyphens = _registered_domain(host).count("-")
    if hyphens >= 1:
        add("Hyphen in domain", 8, f"{hyphens} hyphen(s) in registered domain")

    # 9. Suspicious keywords anywhere in the URL.
    hits = sorted({w for w in SUSPICIOUS_WORDS if w in full})
    if hits:
        add("Phishing keywords", min(5 * len(hits), 20), "Found: " + ", ".join(hits))

    # 10. Very long URL — real links are usually short.
    if len(url) > 75:
        add("Long URL", 10, f"{len(url)} characters")

    # 11. High-entropy host — algorithm-generated junk domain.
    ent = _shannon_entropy(host.replace(".", ""))
    if ent > 4.0:
        add("High-entropy host", 10, f"entropy {ent:.2f}")

    # 12. Deep path.
    depth = len([p for p in path.split("/") if p])
    if depth >= 5:
        add("Deep path", 5, f"{depth} path segments")

    score = sum(s["points"] for s in signals)

    if score >= 50:
        verdict = "Likely Phishing"
    elif score >= 25:
        verdict = "Suspicious"
    else:
        verdict = "Probably Safe"

    return {"url": url, "score": score, "verdict": verdict, "signals": signals}


if __name__ == "__main__":
    # Quick manual check: python detector.py
    for test in [
        "https://google.com",
        "http://paypal.com.verify-account.tk/login@192.168.0.1/secure",
        "http://bit.ly/3xYz",
    ]:
        r = analyze(test)
        print(r["verdict"], r["score"], "-", test)
