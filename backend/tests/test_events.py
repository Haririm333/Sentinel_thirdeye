"""
Unit and Integration Tests for Event Ingestion and Retrieval Endpoints
"""

import uuid
from datetime import datetime, timezone, timedelta
from fastapi import status


def test_submit_valid_event(client, sample_valid_event):
    """Verify that a well-formed API event is accepted and persisted with HTTP 201."""
    response = client.post("/api/v1/events", json=sample_valid_event)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["status"] == "accepted"
    assert data["event_id"] == sample_valid_event["event_id"]
    assert "received_at" in data


def test_get_event_by_id(client, sample_valid_event):
    """Verify single event retrieval returns all fields accurately."""
    event_id = str(uuid.uuid4())
    event_data = sample_valid_event.copy()
    event_data["event_id"] = event_id
    
    # Ingest event
    post_res = client.post("/api/v1/events", json=event_data)
    assert post_res.status_code == status.HTTP_201_CREATED

    # Retrieve event
    get_res = client.get(f"/api/v1/events/{event_id}")
    assert get_res.status_code == status.HTTP_200_OK
    retrieved = get_res.json()
    assert retrieved["event_id"] == event_id
    assert retrieved["source_system"] == event_data["source_system"]
    assert retrieved["service_identity"] == event_data["service_identity"]
    assert retrieved["endpoint"] == event_data["endpoint"]
    assert retrieved["http_method"] == "GET"
    assert retrieved["http_status_code"] == 200
    assert retrieved["request_size_bytes"] == 128
    assert retrieved["response_size_bytes"] == 2048
    assert retrieved["source_ip"] == "10.0.1.15"
    assert retrieved["auth_identity"] == "usr_fin_882"
    assert retrieved["action"] == "READ_VENDOR_RECORD"
    assert retrieved["resource_type"] == "VENDOR"
    assert retrieved["resource_id"] == "vnd_10482"
    assert retrieved["approval_reference"] == "APP-2026-9812"
    assert "payload_hash" in retrieved
    assert retrieved["payload_hash"] is not None


def test_get_nonexistent_event_returns_404(client):
    """Verify that requesting an unknown event_id returns 404 Not Found."""
    random_id = str(uuid.uuid4())
    response = client.get(f"/api/v1/events/{random_id}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    body = response.json()
    assert body["detail"]["error"] == "NotFoundError"
    assert random_id in body["detail"]["message"]


def test_list_events_pagination_and_filtering(client, sample_valid_event):
    """Verify pagination and multi-field query filters."""
    base_id = "b0000000-0000-0000-0000-"
    
    # Ingest 5 events with varied systems and status codes
    test_events = [
        {
            **sample_valid_event,
            "event_id": f"{base_id}{i:012d}",
            "source_system": "LedgerOne" if i % 2 == 0 else "HelpDeskr",
            "service_identity": "srv-ledgerone-core" if i % 2 == 0 else "srv-helpdeskr-agent",
            "http_status_code": 200 if i < 3 else 403,
            "action": f"ACTION_{i}",
            "resource_type": "VENDOR" if i % 2 == 0 else "TICKET",
            "endpoint": f"/api/v1/resource/{i}"
        }
        for i in range(5)
    ]

    for ev in test_events:
        res = client.post("/api/v1/events", json=ev)
        assert res.status_code == status.HTTP_201_CREATED

    # 1. Filter by source_system
    res_lo = client.get("/api/v1/events?source_system=LedgerOne")
    assert res_lo.status_code == status.HTTP_200_OK
    data_lo = res_lo.json()
    assert data_lo["total"] >= 3
    for item in data_lo["items"]:
        assert item["source_system"] == "LedgerOne"

    # 2. Filter by http_status_code
    res_403 = client.get("/api/v1/events?http_status_code=403")
    assert res_403.status_code == status.HTTP_200_OK
    data_403 = res_403.json()
    assert data_403["total"] >= 2
    for item in data_403["items"]:
        assert item["http_status_code"] == 403

    # 3. Pagination limits
    res_page = client.get("/api/v1/events?page=1&limit=2")
    assert res_page.status_code == status.HTTP_200_OK
    data_page = res_page.json()
    assert len(data_page["items"]) == 2
    assert data_page["page"] == 1
    assert data_page["limit"] == 2
