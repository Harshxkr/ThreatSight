from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"


def test_analyze():
    response = client.post(
        "/analyze",
        json={
            "url": "https://microsoft-login-security.xyz/verify",
            "text": "Your account will be suspended. Verify now."
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "score" in data
    assert "level" in data
    assert "verdict" in data
    assert "signals" in data
    assert "reasons" in data

    assert isinstance(data["score"], int)
    assert 0 <= data["score"] <= 100

    assert data["signals"]["nlp"] >= 0
    assert data["signals"]["url"] >= 0
    assert data["signals"]["brand"] >= 0

    assert data["score"] >= 80
    assert data["level"] in {"HIGH", "CRITICAL"}
    assert data["verdict"] == "LIKELY_PHISHING"

    assert len(data["reasons"]) > 0