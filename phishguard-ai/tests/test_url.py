import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.detectors.url_detector import analyze_url


def test_legitimate_https_url():
    result = analyze_url("https://www.google.com")

    assert result["score"] == 0
    assert result["risk_level"] == "LOW"


def test_http_url_is_more_suspicious():
    result = analyze_url("http://example.com")

    assert result["score"] >= 10
    assert "Uses HTTP instead of HTTPS" in result["signals"]


def test_ip_address_url():
    result = analyze_url("http://192.168.1.100/login")

    assert result["score"] >= 30
    assert "Uses an IP address instead of a domain name" in result["signals"]


def test_at_symbol_url():
    result = analyze_url("http://google.com@evil-site.com/login")

    assert result["score"] >= 25
    assert "Contains '@' which can hide the actual destination" in result["signals"]


def test_url_shortener():
    result = analyze_url("https://bit.ly/3Example")

    assert result["score"] >= 20
    assert "Uses a URL shortening service that hides the destination" in result["signals"]


def test_suspicious_keywords():
    result = analyze_url(
        "https://example.com/login/verify/account/password"
    )

    assert result["score"] > 0
    assert any(
        "suspicious security/account keywords" in signal
        for signal in result["signals"]
    )


def test_long_url():
    long_url = (
        "https://example.com/"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/"
        "cccccccccccccccccccccccccccccccccccccccccccccccccc"
    )

    result = analyze_url(long_url)

    assert "URL is unusually long" in result["signals"]


def test_empty_url():
    result = analyze_url("")

    assert result["score"] == 0
    assert result["risk_level"] == "UNKNOWN"
    assert "No URL provided" in result["signals"]


def test_invalid_url():
    result = analyze_url("http://")

    assert result["score"] == 80
    assert result["risk_level"] == "HIGH"


def test_non_string_url():
    with pytest.raises(TypeError):
        analyze_url(None)
