def calculate_risk(
    nlp_result: dict,
    url_result: dict,
    brand_result: dict
) -> dict:

    nlp = float(nlp_result.get("score", 0) or 0)
    url = float(url_result.get("score", 0) or 0)
    brand = float(brand_result.get("score", 0) or 0)

    has_text = nlp_result.get("label") not in {"UNKNOWN", None}

    # ---------------------------------------------------------
    # BASE SCORE
    # ---------------------------------------------------------

    if has_text:
        # Normal message/page analysis.
        score = (
            nlp * 0.40 +
            url * 0.35 +
            brand * 0.25
        )
    else:
        # URL-only analysis.
        score = (
            url * 0.60 +
            brand * 0.40
        )

    score = round(max(0, min(score, 100)))

    # ---------------------------------------------------------
    # HIGH-CONFIDENCE ESCALATION
    # ---------------------------------------------------------

    escalation_reason = None

    # Very strong phishing text + strong brand impersonation.
    if nlp >= 90 and brand >= 80:
        score = max(score, 92)
        escalation_reason = (
            "Very strong phishing message combined with "
            "brand impersonation"
        )

    # Very strong phishing text by itself.
    elif nlp >= 90:
        score = max(score, 85)
        escalation_reason = (
            "Very strong phishing message detected by "
            "the ML model"
        )

    # Strong brand + genuinely suspicious URL.
    elif brand >= 80 and url >= 40:
        score = max(score, 80)
        escalation_reason = (
            "Brand impersonation combined with "
            "strong URL risk"
        )

    # ---------------------------------------------------------
    # IMPORTANT:
    # Do NOT automatically force 75/85 just because a brand
    # name appears.
    #
    # Example:
    #
    #     github.com
    #     github.io user page
    #
    # A brand match by itself is not enough to call something
    # highly dangerous.
    # ---------------------------------------------------------

    elif brand >= 80 and url >= 20:
        score = max(score, 65)
        escalation_reason = (
            "Known-brand indicators combined with "
            "suspicious URL characteristics"
        )

    # Suspicious URL can raise the score, but cannot create
    # an artificial high score from nothing.
    elif url >= 60:
        score = max(score, round(url))

        escalation_reason = (
            "Strong suspicious URL characteristics detected"
        )

    elif url >= 40:
        score = max(score, round(url))

        escalation_reason = (
            "Suspicious URL characteristics detected"
        )

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

    neutral_signals = {
        "No text provided",
        "No known brand impersonation detected",
        "No major suspicious URL characteristics detected",
        "ML model predicts a low phishing probability"
    }

    raw_signals = (
        brand_result.get("signals", []) +
        nlp_result.get("signals", []) +
        url_result.get("signals", [])
    )

    for sig in raw_signals:

        if (
            sig not in neutral_signals
            and sig not in reasons
        ):
            reasons.append(sig)

    if (
        escalation_reason
        and escalation_reason not in reasons
    ):
        reasons.append(escalation_reason)

    if not reasons:
        reasons.append(
            "No major suspicious indicators detected"
        )

    # ---------------------------------------------------------
    # FINAL RESULT
    # ---------------------------------------------------------

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