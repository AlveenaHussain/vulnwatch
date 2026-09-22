"""
API key protection for VulnWatch write (ingestion) endpoints.

The expected key comes from the VULNWATCH_API_KEY environment variable
(stored in .env, passed to the backend container by Docker Compose).
It is never hard-coded in source code.
"""

import logging
import os
import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

logger = logging.getLogger("vulnwatch")

# auto_error=False -> we decide the response ourselves (401), and Swagger
# still shows an "Authorize" button for the X-API-Key header.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(provided_key: str | None = Security(api_key_header)) -> None:
    """Allow the request only if X-API-Key matches VULNWATCH_API_KEY."""
    expected_key = os.getenv("VULNWATCH_API_KEY")

    if not expected_key:
        # Fail closed: a server without a configured key accepts nothing.
        logger.error("VULNWATCH_API_KEY is not set; ingestion endpoints are disabled")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ingestion is not configured",
        )

    # compare_digest takes the same time whether the first or last character
    # is wrong, so an attacker cannot guess the key by measuring response time.
    if not provided_key or not secrets.compare_digest(
        provided_key.encode("utf-8"), expected_key.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
