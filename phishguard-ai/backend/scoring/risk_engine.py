def calculate_risk(nlp_result: dict, url_result: dict, brand_result: dict) -> dict:
    nlp = nlp_result.get("score", 0.0)
    url = url_result.get("score", 0.0)
    brand = brand_result.get("score", 0.0)

    # Initial hackathon weights. Tune using validation/demo cases.
    score = (
        nlp * 0.35 +
        url * 0.35 +
        brand * 0.30
    )

    score_100 = round(score * 100)

    if score_100 < 30:
        level = "LOW"
        verdict = "LOW_RISK"
    elif score_100 < 60:
        level = "SUSPICIOUS"
        verdict = "SUSPICIOUS"
    elif score_100 < 80:
        level = "HIGH"
        verdict = "LIKELY_PHISHING"
    else:
        level = "CRITICAL"
        verdict = "LIKELY_PHISHING"

    reasons = []
    reasons.extend(brand_result.get("signals", []))
    reasons.extend(nlp_result.get("signals", []))
    reasons.extend(url_result.get("signals", []))

    # Remove duplicates while preserving order.
    reasons = list(dict.fromkeys(reasons))

    return {
        "score": score_100,
        "level": level,
        "verdict": verdict,
        "signals": {
            "nlp": round(nlp * 100),
            "url": round(url * 100),
            "brand": round(brand * 100),
            "page": 0
        },
        "reasons": reasons[:8]
    }
