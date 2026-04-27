"""
Fernet-based symmetric encryption for at-rest secrets in `platform_settings`.

Master key from env ``MASTER_ENCRYPTION_KEY`` (32-byte url-safe base64).
If unset, runs in passthrough mode: store/return values verbatim and log a
warning once. This keeps dev installs working without ceremony — production
should always provision the key.

Resolution semantics
--------------------
``encrypt(plaintext)`` returns ``(stored_value, was_encrypted)``.
   - With key configured  → Fernet ciphertext, ``True``
   - Without key          → plaintext, ``False``

``decrypt(stored)`` requires the key when called on ciphertext; raises
``RuntimeError`` if a stored token can't be decrypted (e.g. lost master key).

``mask(value)`` returns ``"••••" + last4`` for safe UI display.
"""
from __future__ import annotations

import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger("crypto")

_MASTER_KEY = os.environ.get("MASTER_ENCRYPTION_KEY", "").strip()
_fernet = None
_warned_missing = False
_warned_invalid = False


def _get_fernet():
    """Lazy-init the Fernet instance (so cryptography import is deferred)."""
    global _fernet, _warned_missing, _warned_invalid
    if _fernet is not None:
        return _fernet
    if not _MASTER_KEY:
        if not _warned_missing:
            logger.warning(
                "MASTER_ENCRYPTION_KEY not set — secrets will be stored "
                "in plaintext. Provision the key in production."
            )
            _warned_missing = True
        return None
    try:
        from cryptography.fernet import Fernet  # noqa: WPS433
        _fernet = Fernet(_MASTER_KEY.encode())
        return _fernet
    except Exception as exc:
        if not _warned_invalid:
            logger.error("MASTER_ENCRYPTION_KEY invalid: %s", exc)
            _warned_invalid = True
        return None


def is_encryption_available() -> bool:
    return _get_fernet() is not None


def encrypt(plaintext: str) -> Tuple[str, bool]:
    """Encrypt for at-rest storage. Returns (stored_value, was_encrypted)."""
    f = _get_fernet()
    if f is None:
        return plaintext, False
    return f.encrypt(plaintext.encode("utf-8")).decode("ascii"), True


def decrypt(stored: str) -> str:
    """Decrypt a Fernet token. Caller asserts the value was encrypted."""
    if not stored:
        return ""
    f = _get_fernet()
    if f is None:
        raise RuntimeError(
            "MASTER_ENCRYPTION_KEY required to decrypt this stored value"
        )
    return f.decrypt(stored.encode("ascii")).decode("utf-8")


def mask(value: Optional[str]) -> str:
    """``'sk-abcdef1234'`` → ``'••••1234'``. Empty input → empty string."""
    if not value:
        return ""
    if len(value) <= 4:
        return "••••"
    return "••••" + value[-4:]
