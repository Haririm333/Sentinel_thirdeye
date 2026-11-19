"""
Routes package exports.
"""

from sentinel.backend.app.routes.health import router as health_router
from sentinel.backend.app.routes.events import router as events_router
from sentinel.backend.app.routes.incidents import router as incidents_router
from sentinel.backend.app.routes.ml import router as ml_router
from sentinel.backend.app.routes.ml_lstm import router as ml_lstm_router
from sentinel.backend.app.routes.bank_approvals import router as bank_approvals_router

__all__ = ["health_router", "events_router", "incidents_router", "ml_router", "ml_lstm_router", "bank_approvals_router"]
