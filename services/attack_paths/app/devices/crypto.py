"""
Fernet-based credential encryption for the device registry.

Mirrors `services/api/app/security/crypto.py`. We expect MASTER_ENCRYPTION_KEY
to be present in the attack-paths pod environment (sourced from the shared
`ti-secrets`). If it isn't, encryption is impossible — registration must
refuse rather than silently storing plaintext.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_MASTER_KEY = os.environ.get("MASTER_ENCRYPTION_KEY", "").strip()
_fernet = None


def _get_fernet():
    global _fernet
    if _fernet is not None:
        return _fernet
    if not _MASTER_KEY:
        return None
    from cryptography.fernet import Fernet
    _fernet = Fernet(_MASTER_KEY.encode())
    return _fernet


def encryption_available() -> bool:
    return _get_fernet() is not None


def encrypt_credentials(creds: Dict[str, Any]) -> str:
    """Serialize → encrypt. Raises if no master key configured."""
    f = _get_fernet()
    if f is None:
        raise RuntimeError(
            "MASTER_ENCRYPTION_KEY not configured — cannot store credentials"
        )
    blob = json.dumps(creds, sort_keys=True).encode("utf-8")
    return f.encrypt(blob).decode("ascii")


def decrypt_credentials(token: str) -> Dict[str, Any]:
    f = _get_fernet()
    if f is None:
        raise RuntimeError(
            "MASTER_ENCRYPTION_KEY not configured — cannot decrypt credentials"
        )
    raw = f.decrypt(token.encode("ascii"))
    return json.loads(raw.decode("utf-8"))


def safe_credential_summary(creds: Dict[str, Any]) -> Dict[str, str]:
    """Return a UI-safe view: keys present + masked values."""
    out: Dict[str, str] = {}
    for k, v in creds.items():
        if not isinstance(v, str) or not v:
            out[k] = ""
            continue
        out[k] = "••••" + v[-4:] if len(v) > 4 else "••••"
    return out
