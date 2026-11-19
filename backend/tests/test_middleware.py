"""
Security Middleware Tests
Tests:
- RequestSizeLimitMiddleware (rejection of oversized payloads with 413)
- SecurityHeadersMiddleware (presence of defensive security headers)
"""

from fastapi import status


def test_security_headers_present(client):
    """Ensure essential defensive security headers are appended to responses."""
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_request_size_limit_rejection(client):
    """Ensure requests exceeding max payload size are rejected with 413."""
    # Attempt to post a simulated payload exceeding 1MB Content-Length
    headers = {"Content-Length": "2000000"}  # 2 MB
    response = client.post("/api/v1/events", content=b"dummy", headers=headers)
    assert response.status_code == 413
    body = response.json()
    assert body["error"] == "PayloadTooLarge"
