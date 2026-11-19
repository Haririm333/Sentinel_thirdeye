"""
Database Engine & Session Management for SENTINEL
Configures SQLAlchemy 2.0 with connection pooling, robust retry/pre-ping,
and safe dependency injection.
"""

import time
import logging
from typing import Generator, Dict, Any
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sentinel.backend.app.config import get_settings

logger = logging.getLogger("sentinel.database")
settings = get_settings()

# Engine configuration with dialect-specific options
engine_kwargs: Dict[str, Any] = {
    "pool_pre_ping": True,  # Checks connection validity before checkout
    "echo": False,          # Keep SQL logs clean; do not echo in production
}

if settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    # PostgreSQL pooling parameters
    engine_kwargs["pool_size"] = settings.DB_POOL_SIZE
    engine_kwargs["max_overflow"] = settings.DB_MAX_OVERFLOW
    engine_kwargs["pool_timeout"] = settings.DB_POOL_TIMEOUT

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency yielding a thread-local database session.
    Guarantees session closure upon request completion.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection() -> Dict[str, Any]:
    """
    Health check helper to verify database connectivity and response time.
    Returns status dict with response time in milliseconds.
    """
    start_time = time.perf_counter()
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {"status": "connected", "latency_ms": latency_ms}
    except Exception as exc:
        logger.error("Database health check failed: %s", str(exc))
        return {"status": "disconnected", "error": "Database unreachable"}


def init_db() -> None:
    """
    Initialize all registered models in the database.
    Useful for local development and test suite setup.
    """
    from sentinel.backend.app.models import base  # Ensure models are imported
    Base.metadata.create_all(bind=engine)
