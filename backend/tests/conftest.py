"""
Pytest Fixtures and Test Harness for SENTINEL
Provides an isolated in-memory SQLite database session and FastAPI TestClient.
Ensures zero side-effects between test runs.
"""

import sys
import os
from pathlib import Path

# Add workspace directory to sys.path so 'sentinel' package is importable
WORKSPACE_DIR = Path(__file__).resolve().parent.parent.parent.parent
if str(WORKSPACE_DIR) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_DIR))

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from sentinel.backend.app.main import app
from sentinel.backend.app.database import Base, get_db
from sentinel.backend.app.models.service_identity import ServiceIdentity

# Test database: isolated in-memory SQLite with single connection thread sharing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    """Create database tables once per test session."""
    Base.metadata.create_all(bind=test_engine)
    
    # Seed standard test service identities
    session = TestingSessionLocal()
    seed_services = [
        ServiceIdentity(
            service_id="srv-ledgerone-core",
            service_name="LedgerOne Core Financial Service",
            source_system="LedgerOne",
            status="ACTIVE"
        ),
        ServiceIdentity(
            service_id="srv-tallybridge-sync",
            service_name="TallyBridge ERP Sync Connector",
            source_system="TallyBridge",
            status="ACTIVE"
        ),
        ServiceIdentity(
            service_id="srv-helpdeskr-agent",
            service_name="HelpDeskr Support Portal API",
            source_system="HelpDeskr",
            status="ACTIVE"
        ),
        ServiceIdentity(
            service_id="srv-tallybridge-suspended",
            service_name="Suspended TallyBridge Connector",
            source_system="TallyBridge",
            status="SUSPENDED"
        )
    ]
    session.add_all(seed_services)
    session.commit()
    session.close()
    
    yield
    
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    """Provide a transactional database session per test with automatic rollback."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    """FastAPI TestClient with overridden get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def sample_valid_event():
    """Returns a valid event payload dictionary."""
    return {
        "event_id": "a0000000-0000-0000-0000-000000000001",
        "timestamp": "2026-11-20T02:00:00Z",
        "source_system": "LedgerOne",
        "service_identity": "srv-ledgerone-core",
        "endpoint": "/api/v1/vendors",
        "http_method": "GET",
        "http_status_code": 200,
        "request_size_bytes": 128,
        "response_size_bytes": 2048,
        "source_ip": "10.0.1.15",
        "auth_identity": "usr_fin_882",
        "action": "READ_VENDOR_RECORD",
        "resource_type": "VENDOR",
        "resource_id": "vnd_10482",
        "approval_reference": "APP-2026-9812"
    }
