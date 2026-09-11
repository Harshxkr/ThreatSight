from .url_detector import analyze_url
from .brand_detector import detect_brand


def analyze_security(url):
    url_result = analyze_url(url)
    brand_result = detect_brand(url)

    url_score = url_result["score"]
    brand_score = brand_result["score"]

    # Brand impersonation is a strong phishing indicator.
    if brand_result["impersonation"]:
        combined_score = max(url_score, brand_score)

        # Add extra risk when both URL and brand analysis
        # detect suspicious characteristics.
        if url_score >= 20:
            combined_score += 10
    else:
        combined_score = url_score

    combined_score = min(combined_score, 100)

    if combined_score <= 30:
        risk_level = "LOW"
    elif combined_score <= 60:
        risk_level = "SUSPICIOUS"
    elif combined_score <= 80:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    signals = []

    for signal in url_result["signals"]:
        if signal not in signals:
            signals.append(signal)

    for signal in brand_result["signals"]:
        if signal not in signals:
            signals.append(signal)

    return {
        "score": combined_score,
        "risk_level": risk_level,
        "brand": brand_result["brand"],
        "impersonation": brand_result["impersonation"],
        "signals": signals
    }


if __name__ == "__main__":
    print("=" * 60)
    print("THREATSIGHT - COMBINED SECURITY ANALYZER TEST")
    print("=" * 60)

    test_urls = [
        "https://www.google.com",
        "http://microsoft-login-security.com/verify",
        "http://192.168.1.100/login",
        "http://google.com@evil-site.com/login",
        "https://google-account-verify.com",
        "https://example.com/login"
    ]

    for i, url in enumerate(test_urls, start=1):
        print("\n" + "-" * 60)
        print(f"TEST URL {i}")
        print("-" * 60)

        print("\nURL:")
        print(url)

        result = analyze_security(url)

        print("\nResult:")
        print(f"Score:         {result['score']}/100")
        print(f"Risk Level:    {result['risk_level']}")
        print(f"Brand:         {result['brand']}")
        print(f"Impersonation: {result['impersonation']}")

        print("\nSignals:")
        for signal in result["signals"]:
            print(f"  - {signal}")