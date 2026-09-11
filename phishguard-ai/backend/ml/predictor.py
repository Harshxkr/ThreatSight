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


def contains_any(text, keywords):
    """
    Check whether any keyword/phrase appears in the text.
    """
    return any(keyword in text for keyword in keywords)


def generate_signals(text, score):
    """
    Generate human-readable explanations for the prediction.

    IMPORTANT:
    These rules explain the prediction.
    They do NOT change the ML score.
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
    # URLs inside message
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
            "risk_level": "LOW", "SUSPICIOUS", "HIGH", "CRITICAL",
            "signals": [...]
        }
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    text = text.strip()

    # --------------------------------------------------------
    # Empty input
    # --------------------------------------------------------

    if not text:
        return {
            "score": 0,
            "label": "UNKNOWN",
            "risk_level": "UNKNOWN",
            "signals": ["No text provided"]
        }

    # --------------------------------------------------------
    # Convert message into TF-IDF features
    # --------------------------------------------------------

    text_tfidf = vectorizer.transform([text])

    # --------------------------------------------------------
    # Get probabilities from Logistic Regression
    #
    # probabilities[0] = legitimate probability
    # probabilities[1] = phishing probability
    # --------------------------------------------------------

    probabilities = model.predict_proba(text_tfidf)[0]

    phishing_probability = probabilities[1]

    # Convert 0-1 probability into 0-100 score
    score = round(phishing_probability * 100)

    # --------------------------------------------------------
    # Determine model classification
    #
    # 50% is the normal decision boundary for binary
    # Logistic Regression classification.
    # --------------------------------------------------------

    if score >= 50:
        label = "PHISHING"
    else:
        label = "LEGITIMATE"

    # --------------------------------------------------------
    # Determine risk level
    # --------------------------------------------------------

    if score <= 30:
        risk_level = "LOW"

    elif score <= 60:
        risk_level = "SUSPICIOUS"

    elif score <= 80:
        risk_level = "HIGH"

    else:
        risk_level = "CRITICAL"

    # --------------------------------------------------------
    # Generate explanations
    # --------------------------------------------------------

    text_lower = text.lower()

    signals = generate_signals(
        text_lower,
        score
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

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
    print("THREATSIGHT - NLP PHISHING DETECTOR TEST")
    print("=" * 60)

    test_messages = [

        # 1. Obvious phishing
        "URGENT! Your account will be suspended. "
        "Click here immediately to verify your password.",

        # 2. Normal message
        "Hi team, the meeting has been moved to 3 PM tomorrow. "
        "Please update your calendar.",

        # 3. Credential phishing
        "Your Microsoft account requires verification. "
        "Please login immediately and enter your password and OTP.",

        # 4. Financial phishing
        "Your payment has failed. "
        "Please click the link below to update your credit card details.",

        # 5. Normal business message
        "Dear team, please find the invoice attached. "
        "We will discuss the payment during tomorrow's meeting."
    ]

    for i, message in enumerate(test_messages, start=1):

        print("\n" + "-" * 60)
        print(f"TEST MESSAGE {i}")
        print("-" * 60)

        print("\nMessage:")
        print(message)

        result = analyze_text(message)

        print("\nResult:")
        print(f"Score:      {result['score']}/100")
        print(f"Label:      {result['label']}")
        print(f"Risk Level: {result['risk_level']}")

        print("\nSignals:")

        for signal in result["signals"]:
            print(f"  - {signal}")