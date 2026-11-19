"""
Health Check and Application Readiness Tests
"""

from fastapi import status


def test_health_check_endpoint(client):
    """Verify /health returns HTTP 200 with database status and latency."""
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert "database" in data
    assert "service" in data
    assert "timestamp" in data
