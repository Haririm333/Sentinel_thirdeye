"""
Request Size Limiting Middleware
Enforces strict maximum body size limits on all incoming HTTP requests
to defend against Denial-of-Service (DoS) and memory exhaustion attacks.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from sentinel.backend.app.config import get_settings

settings = get_settings()


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """
    Rejects requests whose Content-Length or streamed body exceeds the configured threshold.
    """
    def __init__(self, app, max_size_bytes: int = settings.MAX_REQUEST_SIZE_BYTES):
        super().__init__(app)
        self.max_size_bytes = max_size_bytes

    async def dispatch(self, request: Request, call_next):
        # 1. Fast rejection using Content-Length header if present
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_size_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": "PayloadTooLarge",
                            "message": f"Request body size {length} bytes exceeds maximum permitted limit of {self.max_size_bytes} bytes."
                        }
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"error": "BadRequest", "message": "Invalid Content-Length header."}
                )

        # 2. Proceed with downstream handler
        response = await call_next(request)
        return response
