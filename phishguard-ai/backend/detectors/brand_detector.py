import json
import re
from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

BRANDS_PATH = PROJECT_ROOT / "data" / "brands.json"


# ============================================================
# LOAD BRAND DATABASE
# ============================================================

with open(BRANDS_PATH, "r", encoding="utf-8") as file:
    BRANDS = json.load(file)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def normalize_domain(domain):
    """
    Normalize a domain before comparison.
    """

    if not domain:
        return ""

    domain = domain.lower().strip()

    # Remove trailing dot
    domain = domain.rstrip(".")

    # Remove leading www.
    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def extract_hostname(url):
    """
    Extract hostname from a URL.
    """

    url = url.strip()

    # Add scheme if missing
    if not re.match(
        r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
        url
    ):
        url = "http://" + url

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if hostname:
            return normalize_domain(hostname)

    except Exception:
        pass

    return ""


def domain_is_official(hostname, official_domains):
    """
    Check whether the hostname is the official domain
    or a legitimate subdomain of an official domain.

    Example:

        login.microsoft.com
        → legitimate Microsoft domain

        microsoft.com
        → legitimate Microsoft domain

        microsoft-login-security.com
        → NOT legitimate Microsoft domain
    """

    hostname = normalize_domain(hostname)

    for official_domain in official_domains:

        official_domain = normalize_domain(
            official_domain
        )

        if (
            hostname == official_domain
            or hostname.endswith("." + official_domain)
        ):
            return True

    return False


# ============================================================
# BRAND DETECTOR
# ============================================================

def detect_brand(url):
    """
    Detect whether a URL appears to impersonate a known brand.

    Returns:

        {
            "score": 0-100,
            "brand": brand name or None,
            "impersonation": True/False,
            "signals": [...]
        }
    """

    hostname = extract_hostname(url)

    if not hostname:

        return {
            "score": 0,
            "brand": None,
            "impersonation": False,
            "signals": [
                "Unable to extract a valid domain"
            ]
        }

    # --------------------------------------------------------
    # Check every known brand
    # --------------------------------------------------------

    for brand, information in BRANDS.items():

        official_domains = information[
            "official_domains"
        ]

        # ----------------------------------------------------
        # Does the brand name appear in the hostname?
        # ----------------------------------------------------

        brand_pattern = re.escape(brand)

        if not re.search(
            r"(^|[.-])" + brand_pattern + r"([.-]|$)",
            hostname
        ):
            continue

        # ----------------------------------------------------
        # Is this actually an official domain?
        # ----------------------------------------------------

        if domain_is_official(
            hostname,
            official_domains
        ):

            return {
                "score": 0,
                "brand": brand,
                "impersonation": False,
                "signals": [
                    f"Domain belongs to an official {brand} domain"
                ]
            }

        # ----------------------------------------------------
        # Brand found but domain isn't official
        # ----------------------------------------------------

        signals = [
            f"Domain contains the brand name '{brand}'",
            f"Domain is not an official {brand} domain"
        ]

        score = 70

        # ----------------------------------------------------
        # Stronger signal if brand appears with suspicious
        # authentication/security terminology
        # ----------------------------------------------------

        suspicious_terms = [
            "login",
            "signin",
            "verify",
            "verification",
            "secure",
            "account",
            "password",
            "update",
            "confirm",
            "security"
        ]

        matching_terms = []

        for term in suspicious_terms:

            if term in hostname:
                matching_terms.append(term)

        if matching_terms:

            score += 15

            signals.append(
                "Brand name is combined with suspicious "
                "authentication/security terms: "
                + ", ".join(matching_terms[:5])
            )

        # ----------------------------------------------------
        # Hyphenated brand impersonation
        # ----------------------------------------------------

        if "-" in hostname:

            score += 5

            signals.append(
                "Uses a modified or hyphenated domain name"
            )

        # Maximum score
        score = min(score, 100)

        return {
            "score": score,
            "brand": brand,
            "impersonation": True,
            "signals": signals
        }

    # ========================================================
    # No known brand detected
    # ========================================================

    return {
        "score": 0,
        "brand": None,
        "impersonation": False,
        "signals": [
            "No known brand impersonation detected"
        ]
    }


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("THREATSIGHT - BRAND IMPERSONATION DETECTOR TEST")
    print("=" * 60)

    test_urls = [

        # ----------------------------------------------------
        # Legitimate official domains
        # ----------------------------------------------------

        "https://www.microsoft.com",
        "https://login.microsoft.com",
        "https://www.google.com",

        # ----------------------------------------------------
        # Brand impersonation
        # ----------------------------------------------------

        "https://microsoft-login-security.com",
        "https://google-account-verify.com",
        "https://paypal-security-login.com",

        # ----------------------------------------------------
        # Brand in path but not domain
        # ----------------------------------------------------

        "https://example.com/microsoft/login",

        # ----------------------------------------------------
        # Unknown domain
        # ----------------------------------------------------

        "https://random-example-site.com"
    ]

    for i, test_url in enumerate(
        test_urls,
        start=1
    ):

        print("\n" + "-" * 60)
        print(f"TEST URL {i}")
        print("-" * 60)

        print("\nURL:")
        print(test_url)

        result = detect_brand(test_url)

        print("\nResult:")
        print(f"Score:         {result['score']}/100")
        print(f"Brand:         {result['brand']}")
        print(f"Impersonation: {result['impersonation']}")

        print("\nSignals:")

        for signal in result["signals"]:

            print(f"  - {signal}")
