"""
Pydantic Schemas for Service Identities
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class ServiceIdentityBase(BaseModel):
    service_id: str = Field(..., min_length=2, max_length=100)
    service_name: str = Field(..., min_length=2, max_length=150)
    source_system: str = Field(..., min_length=2, max_length=50)
    status: str = Field(default="ACTIVE", max_length=20)
    allowed_ips: Optional[str] = Field(default=None, max_length=500)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ServiceIdentityCreate(ServiceIdentityBase):
    pass


class ServiceIdentityResponse(ServiceIdentityBase):
    id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
