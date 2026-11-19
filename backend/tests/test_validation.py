"""
Validation and Malformed Input Rejection Tests
Verifies that all invalid, malformed, or out-of-spec events are rejected with 422.
"""

from fastapi import status


def test_missing_required_fields_rejected(client, sample_valid_event):
    """Omitting any mandatory field must return HTTP 422 Unprocessable Entity."""
    required_fields = [
        "event_id",
        "timestamp",
        "source_system",
        "service_identity",
        "endpoint",
        "http_method",
        "http_status_code",
        "source_ip",
        "auth_identity",
        "action",
        "resource_type"
    ]

    for field in required_fields:
        payload = sample_valid_event.copy()
        payload["event_id"] = "c0000000-0000-0000-0000-000000000002"
        del payload[field]
        
        response = client.post("/api/v1/events", json=payload)
        assert response.status_code == 422, (
            f"Expected 422 when field '{field}' is omitted, got {response.status_code}"
        )
        data = response.json()
        assert data["error"] == "ValidationError"


def test_invalid_uuid_rejected(client, sample_valid_event):
    """Malformed UUIDs must be rejected."""
    payload = sample_valid_event.copy()
    payload["event_id"] = "not-a-valid-uuid-1234"
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422


def test_invalid_http_method_rejected(client, sample_valid_event):
    """Unsupported HTTP methods must be rejected."""
    payload = sample_valid_event.copy()
    payload["http_method"] = "INVALID_METHOD"
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422


def test_invalid_http_status_code_rejected(client, sample_valid_event):
    """Out-of-range HTTP status codes (<100 or >599) must be rejected."""
    # Under 100
    p1 = sample_valid_event.copy()
    p1["http_status_code"] = 99
    res1 = client.post("/api/v1/events", json=p1)
    assert res1.status_code == 422

    # Over 599
    p2 = sample_valid_event.copy()
    p2["http_status_code"] = 600
    res2 = client.post("/api/v1/events", json=p2)
    assert res2.status_code == 422


def test_invalid_ip_address_rejected(client, sample_valid_event):
    """Syntactically invalid IP addresses must be rejected."""
    payload = sample_valid_event.copy()
    payload["source_ip"] = "999.999.999.999"
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422


def test_endpoint_without_leading_slash_rejected(client, sample_valid_event):
    """API endpoints without a leading '/' must be rejected."""
    payload = sample_valid_event.copy()
    payload["endpoint"] = "api/v1/vendors"
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422


def test_negative_byte_sizes_rejected(client, sample_valid_event):
    """Negative request or response sizes must be rejected."""
    payload = sample_valid_event.copy()
    payload["request_size_bytes"] = -1
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422


def test_unknown_extra_fields_rejected(client, sample_valid_event):
    """Unexpected payload parameters must be strictly forbidden (anti-parameter pollution)."""
    payload = sample_valid_event.copy()
    payload["unexpected_injected_field"] = "malicious_payload"
    response = client.post("/api/v1/events", json=payload)
    assert response.status_code == 422


def test_timestamp_normalization_to_utc(client, sample_valid_event):
    """Events submitted with non-UTC timezone offsets must be stored normalized to UTC."""
    event_id = "d0000000-0000-0000-0000-000000000005"
    payload = sample_valid_event.copy()
    payload["event_id"] = event_id
    # Submit timestamp in +05:30 (IST): 07:30:00 IST is 02:00:00 UTC
    payload["timestamp"] = "2026-11-20T07:30:00+05:30"

    post_res = client.post("/api/v1/events", json=payload)
    assert post_res.status_code == status.HTTP_201_CREATED

    get_res = client.get(f"/api/v1/events/{event_id}")
    assert get_res.status_code == status.HTTP_200_OK
    retrieved = get_res.json()
    assert "2026-11-20T02:00:00" in retrieved["timestamp"]
