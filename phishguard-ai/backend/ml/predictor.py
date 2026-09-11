"""NLP interface.

The current implementation is a hackathon-safe baseline.
Replace the heuristic function with the trained TF-IDF + Logistic
Regression model once teammate 2 finishes training.
"""

URGENT_WORDS = {
    "urgent", "immediately", "now", "warning", "final", "suspended",
    "expire", "expired", "action required", "within 24 hours"
}

CREDENTIAL_WORDS = {
    "password", "verify", "verification", "login", "sign in",
    "otp", "credential", "authenticate", "account"
}

THREAT_WORDS = {
    "suspended", "deleted", "terminated", "blocked", "legal action",
    "locked", "deactivated"
}


def _contains_any(text: str, words: set[str]) -> bool:
    text = text.lower()
    return any(word in text for word in words)


def analyze_text(text: str) -> dict:
    if not text.strip():
        return {
            "score": 0.0,
            "signals": []
        }

    signals = []
    points = 0

    if _contains_any(text, URGENT_WORDS):
        points += 35
        signals.append("Urgent language detected")

    if _contains_any(text, CREDENTIAL_WORDS):
        points += 35
        signals.append("Credential or account verification language detected")

    if _contains_any(text, THREAT_WORDS):
        points += 20
        signals.append("Account threat detected")

    score = min(points / 100, 1.0)

    return {
        "score": score,
        "signals": signals
    }
