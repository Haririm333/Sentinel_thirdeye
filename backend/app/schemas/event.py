"""
Pydantic Schemas for API Activity Event Collection and Retrieval
Enforces rigorous validation rules, normalization, and protection against injection.
"""

from datetime import datetime, timezone
import ipaddress
import re
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator, ConfigDict

# UUID v4 pattern
UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# Standard HTTP methods permitted
ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

# Core monitored systems
KNOWN_SOURCE_SYSTEMS = {"LedgerOne", "HelpDeskr", "TallyBridge"}


class EventBase(BaseModel):
    """Base API event payload fields."""
    event_id: str = Field(
        ...,
        description="Globally unique UUID identifying the API event",
        examples=["550e8400-e29b-41d4-a716-446655440000"]
    )
    timestamp: datetime = Field(
        ...,
        description="Event generation timestamp in ISO 8601 format (UTC)",
        examples=["2026-11-20T02:00:00Z"]
    )
    source_system: str = Field(
        ...,
        min_length=2,
        max_length=50,
        description="Monitored originating system (e.g. LedgerOne, HelpDeskr, TallyBridge)",
        examples=["LedgerOne"]
    )
    service_identity: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Identity of the service client or integration caller",
        examples=["srv-tallybridge-sync"]
    )
    endpoint: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Requested API path (must begin with '/')",
        examples=["/api/v1/vendors"]
    )
    http_method: str = Field(
        ...,
        description="HTTP method of the API call",
        examples=["GET"]
    )
    http_status_code: int = Field(
        ...,
        ge=100,
        le=599,
        description="HTTP response status code returned",
        examples=[200]
    )
    request_size_bytes: int = Field(
        default=0,
        ge=0,
        le=104_857_600,  # 100 MB max logical size
        description="Size of HTTP request body in bytes"
    )
    response_size_bytes: int = Field(
        default=0,
        ge=0,
        le=104_857_600,
        description="Size of HTTP response body in bytes"
    )
    source_ip: str = Field(
        ...,
        description="IPv4 or IPv6 address of the calling client",
        examples=["192.168.1.100"]
    )
    auth_identity: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Authenticated user, token principal, or service account",
        examples=["usr_fin_882"]
    )
    action: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="High-level operational action performed",
        examples=["READ_VENDOR_RECORD"]
    )
    resource_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Target business resource type",
        examples=["VENDOR"]
    )
    resource_id: Optional[str] = Field(
        default=None,
        max_length=255,
        description="Identifier of target entity",
        examples=["vnd_10482"]
    )
    approval_reference: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Approval ticket or governance reference",
        examples=["APP-2026-9812"]
    )

    model_config = ConfigDict(
        extra="forbid",  # Reject unknown fields to block payload parameter pollution
        str_strip_whitespace=True
    )

    @field_validator("event_id")
    @classmethod
    def validate_event_id(cls, v: str) -> str:
        """Validate that event_id is a valid UUID."""
        if not UUID_REGEX.match(v):
            raise ValueError(f"Invalid event_id '{v}'. Must be a valid UUID string.")
        return v.lower()

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp_to_utc(cls, v: datetime) -> datetime:
        """Normalize all timestamps to timezone-aware UTC datetime."""
        if v.tzinfo is None:
            # Naive datetime assumed to be UTC
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        """Ensure endpoint is an absolute API path."""
        if not v.startswith("/"):
            raise ValueError(f"Endpoint must start with '/', got '{v}'")
        return v

    @field_validator("http_method")
    @classmethod
    def validate_http_method(cls, v: str) -> str:
        """Validate and standardize HTTP method."""
        method_upper = v.upper()
        if method_upper not in ALLOWED_HTTP_METHODS:
            raise ValueError(
                f"Unsupported HTTP method '{v}'. Must be one of: {', '.join(sorted(ALLOWED_HTTP_METHODS))}"
            )
        return method_upper

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, v: str) -> str:
        """Validate that source_ip is a syntactically valid IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{v}'")
        return v

    @field_validator("service_identity")
    @classmethod
    def validate_service_identity(cls, v: str) -> str:
        """Ensure service identity conforms to valid identifier characters."""
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", v):
            raise ValueError(
                f"Invalid service_identity '{v}'. Allowed characters: letters, numbers, underscores, dashes, dots."
            )
        return v


class EventCreate(EventBase):
    """Schema for incoming API event creation requests."""
    pass


class EventResponse(EventBase):
    """Schema for retrieved API event."""
    id: int
    received_at: datetime
    payload_hash: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class EventSubmissionResponse(BaseModel):
    """Response returned upon successful event acceptance."""
    status: str = "accepted"
    event_id: str
    received_at: datetime


class EventListResponse(BaseModel):
    """Paginated collection of API events."""
    total: int
    page: int
    limit: int
    pages: int
    items: List[EventResponse]
