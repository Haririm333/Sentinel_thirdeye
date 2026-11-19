"""
API Activity Events Ingestion and Retrieval Routes
Endpoints:
- POST /api/v1/events: Ingest, validate, normalize, and store an API activity event
- GET /api/v1/events: Retrieve events with filtering and pagination
- GET /api/v1/events/{event_id}: Retrieve single event by UUID
"""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from sentinel.backend.app.database import get_db
from sentinel.backend.app.schemas.event import (
    EventCreate,
    EventResponse,
    EventSubmissionResponse,
    EventListResponse
)
from sentinel.backend.app.services.event_service import (
    process_and_store_event,
    get_event_by_id,
    query_events,
    DuplicateEventException,
    ServiceSuspendedException
)

router = APIRouter(prefix="/api/v1/events", tags=["API Events"])


def extract_client_ip(request: Request) -> str:
    """Safely extract remote client IP address."""
    # In direct local dev, request.client.host is trusted
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


@router.post(
    "",
    response_model=EventSubmissionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest an API activity event",
    description=(
        "Accepts structured API activity events from LedgerOne, HelpDeskr, and TallyBridge. "
        "Validates input, normalizes timestamps to UTC, sanitizes sensitive fields, "
        "detects duplicates, and securely stores the record."
    ),
    responses={
        201: {"description": "Event successfully accepted and persisted"},
        400: {"description": "Malformed event payload"},
        409: {"description": "Duplicate event ID collision"},
        413: {"description": "Payload size exceeded"},
        422: {"description": "Validation error"}
    }
)
def submit_event(
    event_in: EventCreate,
    request: Request,
    db: Session = Depends(get_db)
):
    """Ingest, validate, and store a new API activity event."""
    client_ip = extract_client_ip(request)

    try:
        stored_event = process_and_store_event(
            db=db,
            event_in=event_in,
            client_ip=client_ip
        )
        return EventSubmissionResponse(
            status="accepted",
            event_id=stored_event.event_id,
            received_at=stored_event.received_at
        )
    except DuplicateEventException as dup_exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "DuplicateEventError",
                "message": f"An event with event_id '{dup_exc.event_id}' has already been processed.",
                "event_id": dup_exc.event_id
            }
        )
    except ServiceSuspendedException as susp_exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "ServiceSuspendedError",
                "message": f"Service identity '{susp_exc.service_identity}' is currently suspended."
            }
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "error": "ProcessingError",
                "message": "Internal error occurred while processing the event."
            }
        )


@router.get(
    "",
    response_model=EventListResponse,
    summary="Retrieve API activity events with pagination and filters",
    description="Query stored API events with comprehensive security filters."
)
def list_events(
    source_system: Optional[str] = Query(None, description="Filter by originating system"),
    service_identity: Optional[str] = Query(None, description="Filter by service identity"),
    auth_identity: Optional[str] = Query(None, description="Filter by caller auth identity"),
    endpoint: Optional[str] = Query(None, description="Filter by API endpoint substring"),
    action: Optional[str] = Query(None, description="Filter by action performed"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    http_status_code: Optional[int] = Query(None, ge=100, le=599, description="Filter by HTTP status code"),
    start_time: Optional[datetime] = Query(None, description="Filter events after this UTC timestamp"),
    end_time: Optional[datetime] = Query(None, description="Filter events before this UTC timestamp"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    limit: int = Query(50, ge=1, le=100, description="Items per page (max 100)"),
    db: Session = Depends(get_db)
):
    """Retrieve filtered and paginated API events."""
    total, items = query_events(
        db=db,
        source_system=source_system,
        service_identity=service_identity,
        auth_identity=auth_identity,
        endpoint=endpoint,
        action=action,
        resource_type=resource_type,
        http_status_code=http_status_code,
        start_time=start_time,
        end_time=end_time,
        page=page,
        limit=limit
    )

    pages = (total + limit - 1) // limit if total > 0 else 0

    return EventListResponse(
        total=total,
        page=page,
        limit=limit,
        pages=pages,
        items=items
    )


@router.get(
    "/{event_id}",
    response_model=EventResponse,
    summary="Retrieve single API event by ID",
    description="Lookup an individual API activity event by its unique event UUID.",
    responses={
        200: {"description": "Event found"},
        404: {"description": "Event not found"}
    }
)
def get_event(
    event_id: str,
    db: Session = Depends(get_db)
):
    """Retrieve specific event by its unique identifier."""
    event = get_event_by_id(db=db, event_id=event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "error": "NotFoundError",
                "message": f"API event with ID '{event_id}' was not found.",
                "event_id": event_id
            }
        )
    return event
