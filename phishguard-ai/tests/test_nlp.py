from backend.ml.predictor import analyze_text


def test_phishing_text_signals():
    result = analyze_text(
        "URGENT! Your account is suspended. Verify your password immediately."
    )
    assert result["score"] > 0.5
    assert len(result["signals"]) >= 2
