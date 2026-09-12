import re
import joblib
from pathlib import Path


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = PROJECT_ROOT / "backend" / "ml" / "models"

VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.joblib"
MODEL_PATH = MODEL_DIR / "phishing_model.joblib"


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

vectorizer = joblib.load(VECTORIZER_PATH)
model = joblib.load(MODEL_PATH)


# ============================================================
# EXPLAINABILITY RULES
# ============================================================

URGENCY_WORDS = [
    "urgent",
    "immediately",
    "right now",
    "action required",
    "act now",
    "as soon as possible",
    "final warning",
    "important notice",
    "deadline",
    "expire",
    "expired",
]


CREDENTIAL_WORDS = [
    "password",
    "verify your password",
    "login",
    "log in",
    "sign in",
    "credentials",
    "username",
    "otp",
    "verification code",
    "security code",
]


FINANCIAL_WORDS = [
    "payment",
    "invoice",
    "bank",
    "bank account",
    "credit card",
    "debit card",
    "card number",
    "transaction",
    "refund",
    "transfer",
]


LINK_WORDS = [
    "click here",
    "click the link",
    "click on the link",
    "link below",
    "open the link",
    "verify using this link",
]


THREAT_WORDS = [
    "suspended",
    "suspend",
    "blocked",
    "locked",
    "terminated",
    "deactivated",
    "disabled",
    "account will be closed",
]


# ============================================================
# HELPER
# ============================================================

def contains_any(text, keywords):
    """
    Check whether any keyword/phrase appears in the text.
    """

    return any(
        keyword in text
        for keyword in keywords
    )


# ============================================================
# SIGNAL GENERATION
# ============================================================

def generate_signals(text, score):
    """
    Generate human-readable explanations.

    These signals explain the result.
    They do NOT directly change the ML score.
    """

    signals = []

    # --------------------------------------------------------
    # Urgency
    # --------------------------------------------------------

    if contains_any(text, URGENCY_WORDS):
        signals.append(
            "Uses urgent or time-pressure language"
        )

    # --------------------------------------------------------
    # Credential harvesting
    # --------------------------------------------------------

    if contains_any(text, CREDENTIAL_WORDS):
        signals.append(
            "Requests or mentions login credentials or verification codes"
        )

    # --------------------------------------------------------
    # Financial information
    # --------------------------------------------------------

    if contains_any(text, FINANCIAL_WORDS):
        signals.append(
            "Mentions financial or payment-related information"
        )

    # --------------------------------------------------------
    # Suspicious links
    # --------------------------------------------------------

    if contains_any(text, LINK_WORDS):
        signals.append(
            "Encourages the user to click or open a link"
        )

    # --------------------------------------------------------
    # Threats / consequences
    # --------------------------------------------------------

    if contains_any(text, THREAT_WORDS):
        signals.append(
            "Uses account suspension, blocking, or termination threats"
        )

    # --------------------------------------------------------
    # URLs
    # --------------------------------------------------------

    url_pattern = r"https?://\S+|www\.\S+"

    if re.search(url_pattern, text):
        signals.append(
            "Contains a URL"
        )

    # --------------------------------------------------------
    # ML probability explanation
    # --------------------------------------------------------

    if score >= 81:
        signals.append(
            "ML model predicts a very high phishing probability"
        )

    elif score >= 61:
        signals.append(
            "ML model predicts a high phishing probability"
        )

    elif score >= 31:
        signals.append(
            "ML model detected a suspicious message pattern"
        )

    else:
        signals.append(
            "ML model predicts a low phishing probability"
        )

    return signals


# ============================================================
# MAIN NLP ANALYZER
# ============================================================

def analyze_text(text):
    """
    Analyze an email/message and return phishing risk.

    Returns:

        {
            "score": 0-100,
            "label": "LEGITIMATE" or "PHISHING",
            "risk_level":
                "LOW",
                "SUSPICIOUS",
                "HIGH",
                "CRITICAL",
            "signals": [...]
        }
    """

    # --------------------------------------------------------
    # Validate input
    # --------------------------------------------------------

    if not isinstance(text, str):
        raise TypeError(
            "text must be a string"
        )

    text = text.strip()

    # --------------------------------------------------------
    # Empty input
    # --------------------------------------------------------

    if not text:
        return {
            "score": 0,
            "label": "UNKNOWN",
            "risk_level": "UNKNOWN",
            "signals": [
                "No text provided"
            ]
        }

    # --------------------------------------------------------
    # Convert message into TF-IDF features
    # --------------------------------------------------------

    text_tfidf = vectorizer.transform([text])

    # ========================================================
    # ML PROBABILITY
    # ========================================================

    probabilities = model.predict_proba(text_tfidf)[0]

    phishing_probability = float(probabilities[1])

    # ========================================================
    # OUT-OF-DISTRIBUTION PROTECTION
    # ========================================================

    words = text.split()
    word_count = len(words)

    # Number of features from the input recognized by TF-IDF
    recognized_features = text_tfidf.nnz

    # --------------------------------------------------------
    # HIGH-RISK INTENT PATTERNS
    # --------------------------------------------------------

    high_risk_patterns = [

        r"\bpassword\b",

        r"\bpasscode\b",

        r"\bverification code\b",

        r"\botp\b",

        r"\b2fa\b",

        r"\bcredential",

        r"\blogin\b",

        r"\bsign in\b",

        r"\bclick\b",

        r"\breset\b.*\bpassword\b",

        r"\baccount\b.*\bsuspend",

        r"\baccount\b.*\bblock",

        r"\bcredit card\b",

        r"\bcard details\b",

        r"\bpayment\b.*\bfailed\b",
    ]

    lower_text = text.lower()

    has_high_risk_signal = any(
        re.search(
            pattern,
            lower_text
        )
        for pattern in high_risk_patterns
    )

    # ========================================================
    # CASE 1: UNKNOWN / NONSENSE INPUT
    # ========================================================

    if (
        recognized_features == 0
        and not has_high_risk_signal
    ):
        phishing_probability = 0.02

    # ========================================================
    # CASE 2: VERY SHORT ORDINARY LANGUAGE
    # ========================================================

    elif (
        word_count <= 3
        and not has_high_risk_signal
    ):
        phishing_probability = min(
            phishing_probability,
            0.08
        )

    # ========================================================
    # CASE 3: NORMAL LONGER CONVERSATION
    # ========================================================
    #
    # The ML model can still be overconfident on ordinary
    # conversational sentences. If there are no phishing
    # intent signals, keep the score conservative.
    #
    # This prevents messages such as:
    #
    # "I will meet you tomorrow"
    # "Can you send me the report"
    #
    # from becoming false positives.
    # ========================================================

    elif (
        word_count <= 8
        and not has_high_risk_signal
    ):
        phishing_probability = min(
            phishing_probability,
            0.15
        )

    # ========================================================
    # FINAL SCORE
    # ========================================================

    score = round(
        phishing_probability * 100
    )

    score = max(
        0,
        min(
            score,
            100
        )
    )

    # ========================================================
    # CLASSIFICATION
    # ========================================================

    if score >= 50:
        label = "PHISHING"
    else:
        label = "LEGITIMATE"

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
    # SIGNALS
    # ========================================================

    signals = generate_signals(
        lower_text,
        score
    )

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {
        "score": score,
        "label": label,
        "risk_level": risk_level,
        "signals": signals
    }


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "THREATSIGHT - NLP PHISHING DETECTOR TEST"
    )

    print("=" * 60)

    test_messages = [

        # ----------------------------------------------------
        # 1. Obvious phishing
        # ----------------------------------------------------

        (
            "URGENT! Your account will be suspended. "
            "Click here immediately to verify your password."
        ),

        # ----------------------------------------------------
        # 2. Normal message
        # ----------------------------------------------------

        (
            "Hi team, the meeting has been moved to 3 PM tomorrow. "
            "Please update your calendar."
        ),

        # ----------------------------------------------------
        # 3. Credential phishing
        # ----------------------------------------------------

        (
            "Your Microsoft account requires verification. "
            "Please login immediately and enter your password and OTP."
        ),

        # ----------------------------------------------------
        # 4. Financial phishing
        # ----------------------------------------------------

        (
            "Your payment has failed. "
            "Please click the link below to update your credit card details."
        ),

        # ----------------------------------------------------
        # 5. Normal business message
        # ----------------------------------------------------

        (
            "Dear team, please find the invoice attached. "
            "We will discuss the payment during tomorrow's meeting."
        ),

        # ----------------------------------------------------
        # 6. RANDOM / NONSENSE
        # ----------------------------------------------------

        "htnjvknkjd",

        # ----------------------------------------------------
        # 7. ANOTHER RANDOM STRING
        # ----------------------------------------------------

        "xjskqplmzz",

        # ----------------------------------------------------
        # 8. SHORT NORMAL MESSAGE
        # ----------------------------------------------------

        "hello",

        # ----------------------------------------------------
        # 9. SHORT NORMAL MESSAGE
        # ----------------------------------------------------

        "good morning",

        # ----------------------------------------------------
        # 10. NORMAL CONVERSATION
        # ----------------------------------------------------

        "how are you today",

        # ----------------------------------------------------
        # 11. NORMAL CONVERSATION
        # ----------------------------------------------------

        "I will meet you tomorrow",

        # ----------------------------------------------------
        # 12. NORMAL WORK MESSAGE
        # ----------------------------------------------------

        "please send me the project report",

        # ----------------------------------------------------
        # 13. SHORT SUSPICIOUS
        # ----------------------------------------------------

        "verify password",

        # ----------------------------------------------------
        # 14. SHORT SUSPICIOUS
        # ----------------------------------------------------

        "click here to verify your password",

        # ----------------------------------------------------
        # 15. NORMAL CONVERSATION
        # ----------------------------------------------------

        "Can you call me later?",

        # ----------------------------------------------------
        # 16. NORMAL CONVERSATION
        # ----------------------------------------------------

        "Let's meet for lunch tomorrow",

        # ----------------------------------------------------
        # 17. NORMAL WORK MESSAGE
        # ----------------------------------------------------

        "Please review the document when you have time",

        # ----------------------------------------------------
        # 18. PHISHING
        # ----------------------------------------------------

        "Your account is locked. Reset your password immediately.",

        # ----------------------------------------------------
        # 19. PHISHING
        # ----------------------------------------------------

        "Click here to confirm your verification code.",

        # ----------------------------------------------------
        # 20. PHISHING
        # ----------------------------------------------------

        "Your bank account has been suspended. Login to restore access.",
    ]

    # ========================================================
    # RUN TESTS
    # ========================================================

    for i, message in enumerate(
        test_messages,
        start=1
    ):

        print(
            "\n" + "-" * 60
        )

        print(
            f"TEST MESSAGE {i}"
        )

        print(
            "-" * 60
        )

        print(
            "\nMessage:"
        )

        print(
            message
        )

        try:

            result = analyze_text(
                message
            )

            print(
                "\nResult:"
            )

            print(
                f"Score:      "
                f"{result['score']}/100"
            )

            print(
                f"Label:      "
                f"{result['label']}"
            )

            print(
                f"Risk Level: "
                f"{result['risk_level']}"
            )

            print(
                "\nSignals:"
            )

            for signal in result["signals"]:

                print(
                    f"  - {signal}"
                )

        except Exception as e:

            print(
                "\nERROR:"
            )

            print(
                str(e)
            )