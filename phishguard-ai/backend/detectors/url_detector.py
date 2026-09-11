import re
import ipaddress
from urllib.parse import urlparse


# ============================================================
# URL DETECTOR
# ThreatSight - Person 3
# ============================================================


# Common URL shortening services.
# These are not automatically malicious, but they hide the
# final destination and therefore increase suspicion.
SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}


# Suspicious words frequently seen in phishing URLs.
SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "credential",
    "security",
    "authenticate",
    "wallet",
    "payment",
    "billing",
}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def is_ip_address(hostname):
    """
    Check whether the hostname is an IPv4 or IPv6 address.
    """

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False


def get_domain_parts(hostname):
    """
    Split a hostname into useful parts.
    """

    if not hostname:
        return []

    return hostname.split(".")


def is_shortener(hostname):
    """
    Check whether the hostname belongs to a known URL shortener.
    """

    if not hostname:
        return False

    hostname = hostname.lower().rstrip(".")

    return hostname in SHORTENER_DOMAINS


def contains_suspicious_keyword(url):
    """
    Find suspicious words in the URL.

    Returns the matching keywords.
    """

    url_lower = url.lower()

    found = []

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in url_lower:
            found.append(keyword)

    return found


# ============================================================
# MAIN URL ANALYZER
# ============================================================

def analyze_url(url):
    """
    Analyze a URL for phishing-related characteristics.

    Returns:

        {
            "score": 0-100,
            "risk_level": "...",
            "signals": [...]
        }
    """

    # --------------------------------------------------------
    # Validate input
    # --------------------------------------------------------

    if not isinstance(url, str):
        raise TypeError("url must be a string")

    url = url.strip()

    if not url:
        return {
            "score": 0,
            "risk_level": "UNKNOWN",
            "signals": ["No URL provided"]
        }

    # --------------------------------------------------------
    # Add scheme if user provides something like:
    #
    # example.com/login
    # --------------------------------------------------------

    url_to_parse = url

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url_to_parse = "http://" + url

    # --------------------------------------------------------
    # Parse URL
    # --------------------------------------------------------

    try:
        parsed = urlparse(url_to_parse)

    except Exception:
        return {
            "score": 80,
            "risk_level": "HIGH",
            "signals": ["Unable to parse URL safely"]
        }

    hostname = parsed.hostname

    if hostname:
        hostname = hostname.lower().rstrip(".")

    # --------------------------------------------------------
    # Basic validation
    # --------------------------------------------------------

    if not hostname:

        return {
            "score": 80,
            "risk_level": "HIGH",
            "signals": ["URL does not contain a valid hostname"]
        }

    signals = []

    # We'll accumulate points from independent indicators.
    # The final score is capped at 100.
    risk_points = 0

    # ========================================================
    # CHECK 1 — HTTP instead of HTTPS
    # ========================================================

    if parsed.scheme.lower() == "http":

        risk_points += 10

        signals.append(
            "Uses HTTP instead of HTTPS"
        )

    # ========================================================
    # CHECK 2 — IP ADDRESS
    # ========================================================

    if is_ip_address(hostname):

        risk_points += 30

        signals.append(
            "Uses an IP address instead of a domain name"
        )

    # ========================================================
    # CHECK 3 — @ SYMBOL
    # ========================================================

    if "@" in url:

        risk_points += 25

        signals.append(
            "Contains '@' which can hide the actual destination"
        )

    # ========================================================
    # CHECK 4 — VERY LONG URL
    # ========================================================

    if len(url) > 100:

        risk_points += 10

        signals.append(
            "URL is unusually long"
        )

    # ========================================================
    # CHECK 5 — EXTREMELY LONG URL
    # ========================================================

    if len(url) > 200:

        risk_points += 10

        signals.append(
            "URL is extremely long and may contain obfuscation"
        )

    # ========================================================
    # CHECK 6 — MANY SUBDOMAINS
    # ========================================================

    domain_parts = get_domain_parts(hostname)

    # Example:
    #
    # login.security.account.example.com
    #
    # has many domain components.

    if len(domain_parts) >= 5:

        risk_points += 15

        signals.append(
            "Contains an unusually large number of subdomains"
        )

    # ========================================================
    # CHECK 7 — URL SHORTENER
    # ========================================================

    if is_shortener(hostname):

        risk_points += 20

        signals.append(
            "Uses a URL shortening service that hides the destination"
        )

    # ========================================================
    # CHECK 8 — SUSPICIOUS KEYWORDS
    # ========================================================

    suspicious_keywords = contains_suspicious_keyword(url)

    if suspicious_keywords:

        # Maximum contribution from keyword detection = 15
        keyword_points = min(
            len(suspicious_keywords) * 5,
            15
        )

        risk_points += keyword_points

        signals.append(
            "Contains suspicious security/account keywords: "
            + ", ".join(suspicious_keywords[:5])
        )

    # ========================================================
    # CHECK 9 — ENCODED CHARACTERS
    # ========================================================

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        url
    )

    if len(encoded_matches) >= 3:

        risk_points += 10

        signals.append(
            "Contains multiple encoded characters"
        )

    # ========================================================
    # CHECK 10 — SUSPICIOUS PORT
    # ========================================================

    try:

        port = parsed.port

        if port is not None and port not in {80, 443}:

            risk_points += 10

            signals.append(
                f"Uses a non-standard web port ({port})"
            )

    except ValueError:

        risk_points += 15

        signals.append(
            "Contains an invalid port number"
        )

    # ========================================================
    # CHECK 11 — DOUBLE SLASH IN PATH
    # ========================================================

    if "//" in parsed.path:

        risk_points += 5

        signals.append(
            "Contains unusual double slashes in the path"
        )

    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = min(risk_points, 100)

    # ========================================================
    # RISK LEVEL
    # ========================================================

    if score <= 30:

        risk_level = "LOW"

    elif score <= 60:

        risk_level = "SUSPICIOUS"

    elif score <= 80:

        risk_level = "HIGH"

    else:

        risk_level = "CRITICAL"

    # ========================================================
    # NO SUSPICIOUS SIGNALS
    # ========================================================

    if not signals:

        signals.append(
            "No major suspicious URL characteristics detected"
        )

    # ========================================================
    # RESULT
    # ========================================================

    return {
        "score": score,
        "risk_level": risk_level,
        "signals": signals
    }


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("THREATSIGHT - URL SECURITY DETECTOR TEST")
    print("=" * 60)

    test_urls = [

        # 1. Normal HTTPS website
        "https://www.google.com",

        # 2. Suspicious phishing-style domain
        "http://microsoft-login-security.com/verify",

        # 3. IP address
        "http://192.168.1.100/login",

        # 4. @ symbol trick
        "http://google.com@evil-site.com/login",

        # 5. URL shortener
        "https://bit.ly/3Example",

        # 6. Many subdomains
        "https://login.account.security.verify.example.com",

        # 7. Long / suspicious URL
        "http://example.com/login/verify/account/password/"
        "security/update/confirm/user/session/verification",

    ]

    for i, test_url in enumerate(test_urls, start=1):

        print("\n" + "-" * 60)
        print(f"TEST URL {i}")
        print("-" * 60)

        print(f"\nURL:")
        print(test_url)

        result = analyze_url(test_url)

        print("\nResult:")
        print(f"Score:      {result['score']}/100")
        print(f"Risk Level: {result['risk_level']}")

        print("\nSignals:")

        for signal in result["signals"]:

            print(f"  - {signal}")
