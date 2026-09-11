from fastapi.testclient import TestClient

from backend.main import app


client = TestClient(app)


def test_health():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


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

    assert data["score"] == 50
    assert data["level"] == "SUSPICIOUS"
    assert data["verdict"] == "NEEDS_REVIEW"

    assert data["signals"]["nlp"] == 50
    assert data["signals"]["url"] == 50
    assert data["signals"]["brand"] == 50

    assert len(data["reasons"]) > 0


def test_analyze_requires_url():
    response = client.post(
        "/analyze",
        json={
            "text": "Verify your account now."
        }
    )

    assert response.status_code == 422