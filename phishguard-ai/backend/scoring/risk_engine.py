def calculate_risk(
    nlp_result: dict,
    url_result: dict,
    brand_result: dict
) -> dict:

    nlp = nlp_result.get("score", 0)
    url = url_result.get("score", 0)
    brand = brand_result.get("score", 0)

    # ---------------------------------------------------------
    # BASE SCORE
    # ---------------------------------------------------------
    # All detector scores are already on a 0-100 scale.
    score = (
        nlp * 0.35 +
        url * 0.35 +
        brand * 0.30
    )

    score = round(max(0, min(score, 100)))

    # ---------------------------------------------------------
    # HIGH-CONFIDENCE ESCALATION
    # ---------------------------------------------------------
    # A very strong NLP phishing prediction should not be
    # diluted simply because the URL looks legitimate.
    #
    # Strong brand impersonation combined with strong NLP
    # evidence is also treated as critical evidence.
    # ---------------------------------------------------------

    escalation_reason = None

    if nlp >= 90 and brand >= 80:
        score = max(score, 90)
        escalation_reason = (
            "Very strong phishing message combined with "
            "brand impersonation"
        )

    elif nlp >= 90:
        score = max(score, 81)
        escalation_reason = (
            "Very strong phishing message detected by the ML model"
        )

    elif brand >= 80 and url >= 20:
        score = max(score, 81)
        escalation_reason = (
            "Brand impersonation combined with suspicious URL characteristics"
        )

    # Keep score within valid range.
    score = round(max(0, min(score, 100)))

    # ---------------------------------------------------------
    # RISK LEVEL
    # ---------------------------------------------------------

    if score <= 30:
        level = "LOW"
        verdict = "LOW_RISK"

    elif score <= 60:
        level = "SUSPICIOUS"
        verdict = "SUSPICIOUS"

    elif score <= 80:
        level = "HIGH"
        verdict = "LIKELY_PHISHING"

    else:
        level = "CRITICAL"
        verdict = "LIKELY_PHISHING"

    # ---------------------------------------------------------
    # REASONS / EXPLAINABILITY
    # ---------------------------------------------------------

    reasons = []

    reasons.extend(brand_result.get("signals", []))
    reasons.extend(nlp_result.get("signals", []))
    reasons.extend(url_result.get("signals", []))

    if escalation_reason:
        reasons.append(escalation_reason)

    # Remove duplicates while preserving order.
    reasons = list(dict.fromkeys(reasons))

    return {
        "score": score,
        "level": level,
        "verdict": verdict,
        "signals": {
            "nlp": round(nlp),
            "url": round(url),
            "brand": round(brand),
            "page": 0
        },
        "reasons": reasons[:8]
    }