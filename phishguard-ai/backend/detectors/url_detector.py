from urllib.parse import urlparse
import re


SUSPICIOUS_KEYWORDS = {
    "login", "verify", "verification", "secure", "security",
    "account", "update", "password", "confirm", "signin"
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".work", ".zip", ".mov"
}


def analyze_url(url: str) -> dict:
    signals = []
    points = 0

    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        lower_url = url.lower()

        if not parsed.scheme or not host:
            return {"score": 0.8, "signals": ["Malformed or incomplete URL"]}

        if len(url) > 100:
            points += 15
            signals.append("Unusually long URL")

        if host.replace(".", "").isdigit():
            points += 25
            signals.append("IP address used instead of a domain")

        if "@" in url:
            points += 25
            signals.append("URL contains @ character")

        if host.count(".") >= 3:
            points += 10
            signals.append("Many subdomains detected")

        if host.count("-") >= 2:
            points += 10
            signals.append("Multiple hyphens in domain")

        if any(word in lower_url for word in SUSPICIOUS_KEYWORDS):
            points += 15
            signals.append("Credential/account-related URL keywords")

        if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
            points += 20
            signals.append("Higher-risk TLD detected")

        if parsed.scheme != "https":
            points += 10
            signals.append("Connection is not HTTPS")

        return {
            "score": min(points / 100, 1.0),
            "signals": signals
        }

    except Exception:
        return {
            "score": 0.8,
            "signals": ["URL parsing failed"]
        }
