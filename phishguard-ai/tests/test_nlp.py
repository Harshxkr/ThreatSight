import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.ml.predictor import analyze_text


def test_phishing_message():
    message = (
        "URGENT! Your account will be suspended. "
        "Click here immediately to verify your password."
    )

    result = analyze_text(message)

    assert result["score"] >= 80
    assert result["label"] == "PHISHING"
    assert result["risk_level"] in {"HIGH", "CRITICAL"}


def test_legitimate_message():
    message = (
        "Hi team, the meeting has been moved to 3 PM tomorrow. "
        "Please update your calendar."
    )

    result = analyze_text(message)

    assert result["score"] < 50
    assert result["label"] == "LEGITIMATE"


def test_credential_phishing():
    message = (
        "Your Microsoft account requires verification. "
        "Please login immediately and enter your password and OTP."
    )

    result = analyze_text(message)

    assert result["score"] >= 80
    assert result["label"] == "PHISHING"


def test_financial_phishing():
    message = (
        "Your payment has failed. Please click the link below "
        "to update your credit card details."
    )

    result = analyze_text(message)

    assert result["score"] >= 80
    assert result["label"] == "PHISHING"


def test_normal_business_message():
    message = (
        "Dear team, please find the invoice attached. "
        "We will discuss the payment during tomorrow's meeting."
    )

    result = analyze_text(message)

    assert result["score"] < 50
    assert result["label"] == "LEGITIMATE"


def test_empty_message():
    result = analyze_text("")

    assert result["score"] == 0
    assert result["label"] == "UNKNOWN"
    assert result["risk_level"] == "UNKNOWN"
    assert "No text provided" in result["signals"]


def test_whitespace_message():
    result = analyze_text("   ")

    assert result["score"] == 0
    assert result["label"] == "UNKNOWN"
    assert result["risk_level"] == "UNKNOWN"


def test_non_string_message():
    with pytest.raises(TypeError):
        analyze_text(None)


def test_phishing_signals():
    message = (
        "URGENT! Your account has been suspended. "
        "Click here to verify your password."
    )

    result = analyze_text(message)

    assert any(
        "urgent" in signal.lower()
        for signal in result["signals"]
    )

    assert any(
        "credential" in signal.lower()
        for signal in result["signals"]
    )

    assert any(
        "click" in signal.lower()
        for signal in result["signals"]
    )

    assert any(
        "suspension" in signal.lower()
        or "blocking" in signal.lower()
        or "termination" in signal.lower()
        for signal in result["signals"]
    )


def test_result_structure():
    result = analyze_text(
        "Your account requires verification. Please login."
    )

    assert "score" in result
    assert "label" in result
    assert "risk_level" in result
    assert "signals" in result

    assert isinstance(result["score"], int)
    assert isinstance(result["label"], str)
    assert isinstance(result["risk_level"], str)
    assert isinstance(result["signals"], list)
