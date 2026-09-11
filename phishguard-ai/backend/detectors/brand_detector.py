from urllib.parse import urlparse
from rapidfuzz import fuzz


BRANDS = {
    "Microsoft": "microsoft.com",
    "Google": "google.com",
    "Apple": "apple.com",
    "Amazon": "amazon.com",
    "PayPal": "paypal.com",
    "LinkedIn": "linkedin.com",
    "Facebook": "facebook.com",
    "Instagram": "instagram.com",
    "Netflix": "netflix.com",
}


def detect_brand(url: str) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    for brand, official_domain in BRANDS.items():
        brand_token = brand.lower().replace(" ", "")
        similarity = fuzz.partial_ratio(brand_token, host)

        # Brand name appears in host but official domain is not the host.
        if brand_token in host and not host.endswith(official_domain):
            return {
                "score": 0.95,
                "brand": brand,
                "impersonation": True,
                "signals": [f"Possible {brand} impersonation"]
            }

        if similarity >= 85 and not host.endswith(official_domain):
            return {
                "score": 0.85,
                "brand": brand,
                "impersonation": True,
                "signals": [f"Domain resembles {brand}"]
            }

    return {
        "score": 0.0,
        "brand": None,
        "impersonation": False,
        "signals": []
    }
