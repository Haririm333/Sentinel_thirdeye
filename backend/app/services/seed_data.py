"""
Service Identity Registry Seeder
Initializes standard identities for LedgerOne, HelpDeskr, and TallyBridge.
"""

from sqlalchemy.orm import Session
from sentinel.backend.app.database import SessionLocal
from sentinel.backend.app.models.service_identity import ServiceIdentity

SEED_SERVICES = [
    {
        "service_id": "srv-ledgerone-core",
        "service_name": "LedgerOne Core Financial Service",
        "source_system": "LedgerOne",
        "status": "ACTIVE",
        "allowed_ips": "10.0.1.0/24,127.0.0.1"
    },
    {
        "service_id": "srv-ledgerone-paygate",
        "service_name": "LedgerOne Payment Gateway",
        "source_system": "LedgerOne",
        "status": "ACTIVE",
        "allowed_ips": "10.0.1.0/24,127.0.0.1"
    },
    {
        "service_id": "srv-tallybridge-sync",
        "service_name": "TallyBridge ERP Sync Connector",
        "source_system": "TallyBridge",
        "status": "ACTIVE",
        "allowed_ips": "10.0.2.0/24,127.0.0.1"
    },
    {
        "service_id": "srv-helpdeskr-agent",
        "service_name": "HelpDeskr Support Portal API",
        "source_system": "HelpDeskr",
        "status": "ACTIVE",
        "allowed_ips": "10.0.3.0/24,127.0.0.1"
    },
    {
        "service_id": "srv-tallybridge-legacy",
        "service_name": "TallyBridge Deprecated Connector",
        "source_system": "TallyBridge",
        "status": "SUSPENDED",
        "allowed_ips": "127.0.0.1"
    }
]


def seed_service_identities(db: Session = None) -> None:
    """Seed baseline service identities into database if not already present."""
    owns_session = False
    if db is None:
        db = SessionLocal()
        owns_session = True

    try:
        for s_data in SEED_SERVICES:
            existing = db.query(ServiceIdentity).filter_by(service_id=s_data["service_id"]).first()
            if not existing:
                service = ServiceIdentity(**s_data)
                db.add(service)
        db.commit()
    finally:
        if owns_session:
            db.close()


if __name__ == "__main__":
    seed_service_identities()
    print("Baseline service identities seeded successfully.")
