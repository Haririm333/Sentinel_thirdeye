"""
SENTINEL - API Behaviour Monitoring & Suspicious Activity Detection System
Phase 1: Foundation and API Event Collection Application Entry Point
"""

import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinel.backend.app.config import get_settings
from sentinel.backend.app.database import init_db, check_db_connection
from sentinel.backend.app.middleware.request_size_limit import RequestSizeLimitMiddleware
from sentinel.backend.app.middleware.security_headers import SecurityHeadersMiddleware
from sentinel.backend.app.routes.health import router as health_router
from sentinel.backend.app.routes.events import router as events_router

settings = get_settings()

# Configure root logging with standard security hygiene
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("sentinel.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    logger.info("Initializing %s v%s in %s mode...", settings.PROJECT_NAME, settings.VERSION, settings.ENVIRONMENT)
    
    # Initialize database tables
    try:
        init_db()
        db_check = check_db_connection()
        logger.info("Database initialized successfully: %s", db_check)
    except Exception as exc:
        logger.error("Failed to initialize database on startup: %s", str(exc))

    yield
    
    logger.info("Shutting down %s...", settings.PROJECT_NAME)


# Create FastAPI instance with complete OpenAPI/Swagger metadata
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "SENTINEL Phase 1: High-integrity API Activity Event Collection, Validation, "
        "and Storage system. Monitors LedgerOne (Finance), HelpDeskr (Support), "
        "and TallyBridge (Integration software)."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# 1. Register Security Middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_size_bytes=settings.MAX_REQUEST_SIZE_BYTES)

# 2. CORS configuration (Restricted to localhost for development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# 3. Custom Exception Handlers for Safe Error Handling
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """
    Standardize Pydantic validation errors without leaking sensitive raw inputs.
    """
    errors = []
    for err in exc.errors():
        field_path = " -> ".join(str(loc) for loc in err.get("loc", []))
        errors.append({
            "field": field_path,
            "message": err.get("msg"),
            "type": err.get("type")
        })
    return JSONResponse(
        status_code=422,
        content={
            "error": "ValidationError",
            "message": "The incoming payload failed schema validation.",
            "details": errors
        }
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    Catch-all handler ensuring internal server errors never leak stack traces
    or database connection strings to the client.
    """
    logger.error("Unhandled exception during request [%s %s]: %s", request.method, request.url.path, str(exc), exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected server error occurred. This anomaly has been safely logged."
        }
    )


# 4. Include Routers
app.include_router(health_router)
app.include_router(events_router)


if __name__ == "__main__":
    import uvicorn
    # Local services strictly bind to localhost during development
    uvicorn.run(
        "sentinel.backend.app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=False
    )
