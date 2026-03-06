import logging
import uuid

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("lexnebulis")


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        correlation_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.correlation_id = correlation_id
        try:
            response = await call_next(request)
        except Exception as exc:
            logger.exception(
                "Unhandled exception [correlation_id=%s] %s: %s",
                correlation_id,
                type(exc).__name__,
                str(exc),
            )
            response = JSONResponse(
                status_code=500,
                content={
                    "detail": "An internal error occurred. Please contact support.",
                    "correlation_id": correlation_id,
                },
            )
        response.headers["X-Request-ID"] = correlation_id
        return response
