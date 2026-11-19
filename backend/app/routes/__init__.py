"""
Routes package exports.
"""

from sentinel.backend.app.routes.health import router as health_router
from sentinel.backend.app.routes.events import router as events_router

__all__ = ["health_router", "events_router"]
