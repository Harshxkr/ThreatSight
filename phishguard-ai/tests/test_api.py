from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze():
    response = client.post(
        "/analyze",
        json={
            "url": "https://microsoft-login-security.xyz/verify",
            "text": "URGENT! Your account will be suspended. Verify your password now."
        }
    )
    assert response.status_code == 200
    assert 0 <= response.json()["score"] <= 100
