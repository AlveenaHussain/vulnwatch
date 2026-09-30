"""
API key protection for VulnWatch protected API endpoints.

The expected key comes from the VULNWATCH_API_KEY environment variable
(stored in .env, passed to the backend container by Docker Compose).

The API key is never hard-coded in source code.
"""

import logging
import os
import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader


logger = logging.getLogger("vulnwatch")


# auto_error=False -> we decide the response ourselves.
# Swagger still exposes the X-API-Key header through the Authorize button.
api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
)


def require_api_key(
    provided_key: str | None = Security(api_key_header),
) -> None:
    """
    Allow the request only when X-API-Key matches
    the VULNWATCH_API_KEY environment variable.
    """

    expected_key = os.getenv("VULNWATCH_API_KEY")

    # Fail closed:
    # if the backend has no configured API key, protected
    # endpoints must not accept requests.
    if not expected_key:
        logger.error(
            "VULNWATCH_API_KEY is not set; "
            "protected API endpoints are disabled"
        )

        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured",
        )

    # Constant-time comparison prevents timing-based
    # comparison attacks.
    if not provided_key or not secrets.compare_digest(
        provided_key.encode("utf-8"),
        expected_key.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )