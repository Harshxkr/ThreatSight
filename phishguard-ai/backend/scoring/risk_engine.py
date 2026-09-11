def calculate_risk(nlp_score: int, url_score: int, brand_score: int) -> dict:
    """
    Combine individual security signals into one ThreatSight risk score.
    """

    final_score = round(
        (nlp_score * 0.35)
        + (url_score * 0.35)
        + (brand_score * 0.30)
    )

    # Keep score safely within 0–100.
    final_score = max(0, min(100, final_score))

    if final_score <= 30:
        level = "LOW"
        verdict = "LIKELY_SAFE"

    elif final_score <= 60:
        level = "SUSPICIOUS"
        verdict = "NEEDS_REVIEW"

    elif final_score <= 80:
        level = "HIGH"
        verdict = "LIKELY_PHISHING"

    else:
        level = "CRITICAL"
        verdict = "LIKELY_PHISHING"

    return {
        "score": final_score,
        "level": level,
        "verdict": verdict
    }