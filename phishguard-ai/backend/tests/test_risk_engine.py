from backend.ml.predictor import analyze_text
from backend.scoring.risk_engine import calculate_risk


def test_case(name, text, url_score, brand_score):
    nlp_result = analyze_text(text)

    url_result = {
        "score": url_score,
        "signals": []
    }

    brand_result = {
        "score": brand_score,
        "signals": []
    }

    result = calculate_risk(
        nlp_result,
        url_result,
        brand_result
    )

    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    print("Message:", text)
    print("NLP Score:", nlp_result["score"])
    print("URL Score:", url_score)
    print("Brand Score:", brand_score)

    print("\nFINAL RESULT")
    print("Score:", result["score"])
    print("Level:", result["level"])
    print("Verdict:", result["verdict"])

    print("\nReasons:")
    for reason in result["reasons"]:
        print(" -", reason)


if __name__ == "__main__":

    # --------------------------------------------------------
    # 1. RANDOM TEXT
    # --------------------------------------------------------

    test_case(
        "RANDOM TEXT",
        "htnjvknkjd",
        0,
        0
    )

    # --------------------------------------------------------
    # 2. NORMAL MESSAGE
    # --------------------------------------------------------

    test_case(
        "NORMAL MESSAGE",
        "Hello, I will meet you tomorrow.",
        0,
        0
    )

    # --------------------------------------------------------
    # 3. NORMAL MESSAGE + BRAND
    # --------------------------------------------------------

    test_case(
        "NORMAL MESSAGE + BRAND",
        "Please check the GitHub project when you have time.",
        0,
        80
    )

    # --------------------------------------------------------
    # 4. BRAND + SUSPICIOUS URL
    # --------------------------------------------------------

    test_case(
        "BRAND + SUSPICIOUS URL",
        "",
        50,
        80
    )

    # --------------------------------------------------------
    # 5. STRONG PHISHING MESSAGE
    # --------------------------------------------------------

    test_case(
        "STRONG PHISHING",
        "URGENT! Your account is suspended. "
        "Click here to verify your password immediately.",
        0,
        0
    )

    # --------------------------------------------------------
    # 6. STRONG PHISHING + URL
    # --------------------------------------------------------

    test_case(
        "STRONG PHISHING + URL",
        "Your account has been locked. "
        "Click here to reset your password immediately.",
        70,
        90
    )

    # --------------------------------------------------------
    # 7. RANDOM TEXT + SUSPICIOUS URL
    # --------------------------------------------------------

    test_case(
        "RANDOM TEXT + SUSPICIOUS URL",
        "htnjvknkjd",
        30,
        0
    )

    # --------------------------------------------------------
    # 8. NORMAL BUSINESS MESSAGE
    # --------------------------------------------------------

    test_case(
        "NORMAL BUSINESS",
        "Dear team, please find the invoice attached. "
        "We will discuss the payment tomorrow.",
        0,
        0
    )