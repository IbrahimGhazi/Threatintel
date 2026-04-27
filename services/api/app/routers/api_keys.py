"""
BYO API key management endpoints.

Stores third-party threat-intel feed API keys in ``platform_settings``,
encrypted-at-rest with Fernet. Plaintext values never leave the API server —
GET responses contain only the last-4 chars + status + source.

Endpoints (all require X-API-Key)::

    GET    /system/api-keys                 → list 7 providers + status
    PUT    /system/api-keys/{provider_id}   → set value (encrypts before storing)
    DELETE /system/api-keys/{provider_id}   → clear DB value (env fallback resumes)
    GET    /system/api-keys/_diag/encryption → reports MASTER_ENCRYPTION_KEY availability

Resolution order at consumer services (ingestion / sandbox)::

    1. DB value (decrypted)  →  if non-empty, use this
    2. Env var fallback      →  legacy .env behaviour
    3. None                  →  feature disabled, no crash
"""
from __future__ import annotations

import os
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_api_key
from app.security.crypto import (
    decrypt,
    encrypt,
    is_encryption_available,
    mask,
)

router = APIRouter(prefix="/system/api-keys", tags=["System"])


# Catalogue of supported providers — keep in sync with frontend.
# `consumer` indicates which service reads the key, used by the UI to set
# the "applies after restart of X" hint after a save.
PROVIDERS = [
    {"id": "abuseipdb",     "label": "AbuseIPDB",
     "env": "ABUSEIPDB_API_KEY",     "url": "https://www.abuseipdb.com/api",
     "consumer": "ingestion"},
    {"id": "otx",           "label": "AlienVault OTX",
     "env": "OTX_API_KEY",           "url": "https://otx.alienvault.com",
     "consumer": "ingestion"},
    {"id": "threatfox",     "label": "ThreatFox",
     "env": "THREATFOX_API_KEY",     "url": "https://threatfox.abuse.ch",
     "consumer": "ingestion"},
    {"id": "malwarebazaar", "label": "MalwareBazaar",
     "env": "MALWAREBAZAAR_API_KEY", "url": "https://bazaar.abuse.ch",
     "consumer": "ingestion"},
    {"id": "urlhaus",       "label": "URLHaus",
     "env": "URLHAUS_API_KEY",       "url": "https://urlhaus.abuse.ch",
     "consumer": "ingestion"},
    {"id": "openphish",     "label": "OpenPhish",
     "env": "OPENPHISH_API_KEY",     "url": "https://openphish.com",
     "consumer": "ingestion"},
    {"id": "virustotal",    "label": "VirusTotal",
     "env": "VIRUSTOTAL_API_KEY",    "url": "https://www.virustotal.com/api",
     "consumer": "sandbox"},
]
_PROVIDER_IDS = {p["id"] for p in PROVIDERS}


# ── Schemas ───────────────────────────────────────────────────────────────────

class SetKeyIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=512,
                       description="Plaintext API key. Will be encrypted "
                                   "before storage. Never logged.")


class KeyOut(BaseModel):
    id: str
    label: str
    env_var: str
    upstream_url: str
    consumer: str          # "ingestion" | "sandbox"
    status: str            # "ui" | "env" | "empty"
    masked: Optional[str]  # None when status == "empty"
    updated_at: Optional[str]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=List[KeyOut])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
) -> List[KeyOut]:
    """Return all 7 providers with status + masked tail (no plaintext)."""
    rows = (await db.execute(
        text("""
            SELECT key, value, value_encrypted, updated_at
            FROM platform_settings
            WHERE key LIKE 'api_key.%'
        """),
    )).fetchall()
    db_map = {r.key.split("api_key.", 1)[1]: r for r in rows}

    out: List[KeyOut] = []
    for p in PROVIDERS:
        row = db_map.get(p["id"])
        env_val = os.environ.get(p["env"], "").strip()

        plaintext = ""
        source = "empty"
        masked: Optional[str] = None
        updated: Optional[str] = None

        if row and row.value:
            try:
                plaintext = decrypt(row.value) if row.value_encrypted else row.value
            except Exception:
                # Encrypted blob but master key missing/wrong — surface to UI
                # without crashing the whole list endpoint.
                plaintext = ""
                masked = "decrypt-error"
                source = "ui"

            if plaintext:
                source = "ui"
                masked = mask(plaintext)
                updated = row.updated_at.isoformat() if row.updated_at else None

        if not plaintext and env_val:
            source = "env"
            masked = mask(env_val)

        out.append(KeyOut(
            id=p["id"], label=p["label"], env_var=p["env"],
            upstream_url=p["url"], consumer=p["consumer"],
            status=source, masked=masked, updated_at=updated,
        ))
    return out


@router.put("/{provider_id}")
async def set_api_key(
    provider_id: str,
    body: SetKeyIn,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Encrypt and persist a key. Overwrites any prior value."""
    if provider_id not in _PROVIDER_IDS:
        raise HTTPException(404, f"unknown provider {provider_id!r}")

    value = body.value.strip()
    if not value:
        raise HTTPException(422, "value cannot be empty")

    stored, was_encrypted = encrypt(value)

    await db.execute(
        text("""
            INSERT INTO platform_settings (key, value, value_encrypted)
            VALUES (:k, :v, :e)
            ON CONFLICT (key) DO UPDATE
                SET value           = EXCLUDED.value,
                    value_encrypted = EXCLUDED.value_encrypted,
                    updated_at      = NOW()
        """),
        {"k": f"api_key.{provider_id}", "v": stored, "e": was_encrypted},
    )
    await db.commit()

    consumer = next(p["consumer"] for p in PROVIDERS if p["id"] == provider_id)
    return {
        "id": provider_id,
        "status": "ui",
        "masked": mask(value),
        "consumer": consumer,
        "encrypted": was_encrypted,
        "message": (
            f"Saved. {consumer.title()} service will pick up the new key "
            "on next pod restart."
        ),
    }


@router.delete("/{provider_id}")
async def clear_api_key(
    provider_id: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """Clear the DB-stored value. Env-var fallback (if any) takes over."""
    if provider_id not in _PROVIDER_IDS:
        raise HTTPException(404, f"unknown provider {provider_id!r}")

    await db.execute(
        text("""
            UPDATE platform_settings
               SET value = '', updated_at = NOW()
             WHERE key = :k
        """),
        {"k": f"api_key.{provider_id}"},
    )
    await db.commit()
    return {"id": provider_id, "status": "cleared"}


@router.get("/_diag/encryption")
async def encryption_diag(_: str = Depends(require_api_key)):
    """Reports whether MASTER_ENCRYPTION_KEY is configured. UI shows a
    warning banner when this returns ``available: false``."""
    return {"available": is_encryption_available()}
