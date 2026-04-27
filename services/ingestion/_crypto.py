"""
Fernet decryption helper for the ingestion service.

Mirrors ``services/api/app/security/crypto.py``. Kept as a flat module so the
docker build context for ingestion stays self-contained (no shared package).

Reads ``MASTER_ENCRYPTION_KEY`` from env. If missing, ``decrypt`` falls back
to passthrough — but only when ``value_encrypted`` was False at the call site.
The caller is responsible for honouring that flag.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("ingestion.crypto")

_MASTER_KEY = os.environ.get("MASTER_ENCRYPTION_KEY", "").strip()
_fernet = None
_warned = False


def _get_fernet():
    global _fernet, _warned
    if _fernet is not None:
        return _fernet
    if not _MASTER_KEY:
        return None
    try:
        from cryptography.fernet import Fernet  # noqa: WPS433
        _fernet = Fernet(_MASTER_KEY.encode())
        return _fernet
    except Exception as exc:
        if not _warned:
            logger.error("MASTER_ENCRYPTION_KEY invalid: %s", exc)
            _warned = True
        return None


def decrypt(stored: str) -> str:
    """Decrypt a Fernet token. Empty input → empty output."""
    if not stored:
        return ""
    f = _get_fernet()
    if f is None:
        raise RuntimeError(
            "MASTER_ENCRYPTION_KEY required to decrypt this stored value"
        )
    return f.decrypt(stored.encode("ascii")).decode("utf-8")
