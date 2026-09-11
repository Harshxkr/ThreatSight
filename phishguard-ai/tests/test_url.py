from backend.detectors.url_detector import analyze_url


def test_suspicious_url():
    result = analyze_url("http://192.168.1.10/login?verify=password")
    assert result["score"] > 0
    assert len(result["signals"]) > 0
