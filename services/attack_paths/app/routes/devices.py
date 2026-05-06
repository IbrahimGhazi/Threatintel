"""
Device-registry CRUD + on-demand fetch.

Internal endpoints (the api service is the only caller):

  POST   /internal/devices                register a new device
  GET    /internal/devices                list all
  GET    /internal/devices/{id}           detail
  PATCH  /internal/devices/{id}           update (re-encrypts creds if supplied)
  DELETE /internal/devices/{id}           remove
  POST   /internal/devices/{id}/fetch     poll right now (returns status)
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import sqlalchemy as sa
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field

from app.auth import require_api_key
from app.db import AsyncSessionLocal
from app.devices.crypto import (
    decrypt_credentials, encrypt_credentials,
    encryption_available, safe_credential_summary,
)
from app.devices.poll import poll_device

log = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/devices", tags=["internal"],
                   dependencies=[Depends(require_api_key)])


# ── Schemas ──────────────────────────────────────────────────────────────────

class DeviceIn(BaseModel):
    vendor: str = Field(..., pattern="^(panos|f5|fortinet)$")
    hostname: str = Field(..., min_length=1, max_length=255)
    address: str = Field(..., min_length=1, max_length=255)
    port: int = 443
    verify_tls: bool = False
    poll_interval_seconds: int = 3600
    enabled: bool = True
    notes: Optional[str] = None
    created_by: Optional[str] = None
    # Credentials shape:
    #   PA: {"api_key": "..."} OR {"user": "...", "password": "..."}
    #   F5: {"user": "...", "password": "..."}
    credentials: Dict[str, str]


class DevicePatch(BaseModel):
    hostname: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = None
    verify_tls: Optional[bool] = None
    poll_interval_seconds: Optional[int] = None
    enabled: Optional[bool] = None
    notes: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None


class DeviceOut(BaseModel):
    id: uuid.UUID
    vendor: str
    role: str
    hostname: str
    address: str
    port: int
    verify_tls: bool
    enabled: bool
    poll_interval_seconds: int
    last_polled_at: Optional[datetime] = None
    last_status: str
    last_error: Optional[str] = None
    last_config_sha256: Optional[str] = None
    last_upload_id: Optional[uuid.UUID] = None
    last_run_id: Optional[uuid.UUID] = None
    is_edge: bool
    notes: Optional[str] = None
    created_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    # never returns plaintext — only "shape + last4" per credential field
    credentials_summary: Dict[str, str] = Field(default_factory=dict)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _row_to_out(r) -> DeviceOut:
    try:
        creds = decrypt_credentials(r.credentials_encrypted)
        summary = safe_credential_summary(creds)
    except Exception:
        summary = {}
    return DeviceOut(
        id=r.id, vendor=r.vendor, role=r.role,
        hostname=r.hostname, address=r.address, port=r.port,
        verify_tls=r.verify_tls, enabled=r.enabled,
        poll_interval_seconds=r.poll_interval_seconds,
        last_polled_at=r.last_polled_at,
        last_status=r.last_status,
        last_error=r.last_error,
        last_config_sha256=r.last_config_sha256,
        last_upload_id=r.last_upload_id,
        last_run_id=r.last_run_id,
        is_edge=r.is_edge,
        notes=r.notes, created_by=r.created_by,
        created_at=r.created_at, updated_at=r.updated_at,
        credentials_summary=summary,
    )


def _validate_credentials(vendor: str, creds: Dict[str, str]) -> None:
    if vendor == "panos":
        if not creds.get("api_key") and not (creds.get("user") and creds.get("password")):
            raise HTTPException(400,
                detail="PAN-OS requires either api_key OR user+password")
    elif vendor == "f5":
        if not (creds.get("user") and creds.get("password")):
            raise HTTPException(400,
                detail="F5 requires user and password")
    elif vendor == "fortinet":
        # Not yet supported; reject explicitly so the UI can show a clear msg.
        raise HTTPException(400,
            detail="Fortinet polling is not yet supported (see vault TODO)")


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("", response_model=DeviceOut)
async def create_device(payload: DeviceIn) -> DeviceOut:
    if not encryption_available():
        raise HTTPException(500,
            detail="MASTER_ENCRYPTION_KEY not configured on attack-paths pod")
    _validate_credentials(payload.vendor, payload.credentials)
    role = "firewall" if payload.vendor in ("panos", "fortinet") else "loadbalancer"
    enc = encrypt_credentials(payload.credentials)
    new_id = uuid.uuid4()
    async with AsyncSessionLocal() as db:
        try:
            await db.execute(sa.text("""
                INSERT INTO topology_devices (
                    id, vendor, role, hostname, address, port, verify_tls,
                    credentials_encrypted, enabled, poll_interval_seconds,
                    notes, created_by
                ) VALUES (
                    :id, :v, :r, :h, :a, :p, :tls, :enc, :en, :interval,
                    :notes, :cb
                )
            """), {
                "id": str(new_id), "v": payload.vendor, "r": role,
                "h": payload.hostname, "a": payload.address, "p": payload.port,
                "tls": payload.verify_tls, "enc": enc,
                "en": payload.enabled, "interval": payload.poll_interval_seconds,
                "notes": payload.notes, "cb": payload.created_by,
            })
            await db.commit()
        except sa.exc.IntegrityError as exc:
            raise HTTPException(409,
                detail=f"a device with this address+port already exists") from exc

    # Fire an immediate poll so the operator sees status feedback right away.
    # Errors are recorded on the device row; we surface them in the response.
    try:
        await poll_device(new_id, reason="initial-after-register")
    except Exception:                                           # noqa: BLE001
        log.exception("initial poll for %s failed", new_id)

    return await _get_one_or_404(new_id)


@router.get("", response_model=List[DeviceOut])
async def list_devices() -> List[DeviceOut]:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(sa.text("""
            SELECT * FROM topology_devices ORDER BY created_at DESC
        """))).fetchall()
        return [_row_to_out(r) for r in rows]


@router.get("/{device_id}", response_model=DeviceOut)
async def get_device(device_id: uuid.UUID) -> DeviceOut:
    return await _get_one_or_404(device_id)


@router.patch("/{device_id}", response_model=DeviceOut)
async def update_device(device_id: uuid.UUID, payload: DevicePatch) -> DeviceOut:
    set_parts: List[str] = []
    params: Dict[str, Any] = {"id": str(device_id)}
    for f in ("hostname", "address", "port", "verify_tls",
              "poll_interval_seconds", "enabled", "notes"):
        v = getattr(payload, f)
        if v is not None:
            set_parts.append(f"{f} = :{f}")
            params[f] = v
    if payload.credentials is not None:
        # Validate against the current vendor (read first)
        async with AsyncSessionLocal() as db:
            row = (await db.execute(sa.text("""
                SELECT vendor FROM topology_devices WHERE id = :id
            """), {"id": str(device_id)})).fetchone()
            if row is None:
                raise HTTPException(404, detail="device not found")
            _validate_credentials(row.vendor, payload.credentials)
        set_parts.append("credentials_encrypted = :enc")
        params["enc"] = encrypt_credentials(payload.credentials)
    if not set_parts:
        return await _get_one_or_404(device_id)
    async with AsyncSessionLocal() as db:
        result = await db.execute(sa.text(f"""
            UPDATE topology_devices SET {", ".join(set_parts)}
            WHERE id = :id
        """), params)
        if result.rowcount == 0:
            raise HTTPException(404, detail="device not found")
        await db.commit()
    return await _get_one_or_404(device_id)


@router.delete("/{device_id}", status_code=204, response_class=Response)
async def delete_device(device_id: uuid.UUID):
    async with AsyncSessionLocal() as db:
        result = await db.execute(sa.text("""
            DELETE FROM topology_devices WHERE id = :id
        """), {"id": str(device_id)})
        if result.rowcount == 0:
            raise HTTPException(404, detail="device not found")
        await db.commit()
    return Response(status_code=204)


@router.post("/{device_id}/fetch")
async def fetch_now(device_id: uuid.UUID) -> Dict[str, Any]:
    try:
        return await poll_device(device_id, reason="manual")
    except ValueError as exc:
        raise HTTPException(404, detail=str(exc)) from exc


# ── Internal helpers ─────────────────────────────────────────────────────────

async def _get_one_or_404(device_id: uuid.UUID) -> DeviceOut:
    async with AsyncSessionLocal() as db:
        row = (await db.execute(sa.text("""
            SELECT * FROM topology_devices WHERE id = :id
        """), {"id": str(device_id)})).fetchone()
        if row is None:
            raise HTTPException(404, detail="device not found")
        return _row_to_out(row)
