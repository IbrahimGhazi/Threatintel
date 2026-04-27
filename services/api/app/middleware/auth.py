"""
API key authentication dependency.
Reads the X-API-Key header and validates it against the configured key.
EDL endpoints and /health are unauthenticated by design (consumed by security devices).
"""
import logging
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import get_settings

logger = logging.getLogger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    settings = get_settings()
    if not api_key or api_key != settings.api_key:
        logger.warning("Rejected request with invalid API key")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key. Provide X-API-Key header.",
        )
    return api_key
