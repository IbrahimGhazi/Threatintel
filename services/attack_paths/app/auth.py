"""
Internal API key auth — same X-API-Key shared with the api service.
"""
import logging
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app.config import get_settings

log = logging.getLogger(__name__)

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    settings = get_settings()
    if not api_key or api_key != settings.api_key:
        log.warning("attack-paths rejected request with invalid API key")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key.",
        )
    return api_key
