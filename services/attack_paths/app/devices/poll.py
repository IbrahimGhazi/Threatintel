"""
Single device poll: fetch → sha256-diff → write upload row → update status.

Used by both the periodic scheduler and the on-demand "Fetch now" endpoint.
Returns the new upload_id when a fresh config landed, else None.
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import sqlalchemy as sa

from app.config import get_settings
from app.db import AsyncSessionLocal
from app.devices import f5_client, panos_client
from app.devices.crypto import decrypt_credentials

log = logging.getLogger(__name__)

_EDGE_ZONE_RE = re.compile(r"^(untrust|outside|wan|internet|external)$", re.I)


def detect_edge_role(config_bytes: bytes, vendor: str) -> bool:
    """
    Quick heuristic for "is this device internet-facing?" — used to mark
    `topology_devices.is_edge` so the UI can highlight edge devices.

    PAN-OS: search for <zone><entry name="X"> where X matches an edge name.
    F5:     LB devices are often edge by default; treat as edge if any
            virtual server has an RFC1918 address (private) → False, else True.
    """
    text = config_bytes.decode("utf-8", errors="replace")
    if vendor == "panos":
        for m in re.finditer(r'<entry\s+name\s*=\s*"([^"]+)"', text):
            if _EDGE_ZONE_RE.match(m.group(1).strip()):
                return True
        return False
    if vendor == "f5":
        # If any virtual destination is a public IP (not 10/8, 172.16/12, 192.168/16),
        # consider it edge.
        for m in re.finditer(r"destination\s+(\d+\.\d+\.\d+\.\d+):\d+", text):
            ip = m.group(1)
            if not _is_rfc1918(ip):
                return True
        return False
    return False


def _is_rfc1918(ip: str) -> bool:
    try:
        a, b, *_ = (int(p) for p in ip.split("."))
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    return False


async def poll_device(device_id: uuid.UUID, *,
                      reason: str = "scheduled") -> Dict[str, Any]:
    """
    Pull the current config from one registered device, store as an upload
    row when changed, update device telemetry. Always succeeds in updating
    the device's status — exceptions are caught and recorded.

    Returns a small status dict the caller can surface in API responses.
    """
    settings = get_settings()
    config_dir = Path(settings.attack_paths_config_dir)

    async with AsyncSessionLocal() as db:
        row = (await db.execute(sa.text("""
            SELECT id, vendor, hostname, address, port, verify_tls,
                   credentials_encrypted, last_config_sha256, enabled
            FROM topology_devices WHERE id = :id
        """), {"id": str(device_id)})).fetchone()
        if row is None:
            raise ValueError(f"device {device_id} not found")
        if not row.enabled:
            return {"device_id": str(device_id), "skipped": "disabled"}

        try:
            credentials = decrypt_credentials(row.credentials_encrypted)
        except Exception as exc:                                    # noqa: BLE001
            log.exception("credential decrypt failed for %s", device_id)
            await _set_status(db, device_id, "auth_failed",
                              f"credential decrypt error: {exc}")
            await db.commit()
            return {"device_id": str(device_id), "ok": False,
                    "error": "credential decrypt failed"}

        # Pick vendor client
        try:
            if row.vendor == "panos":
                fetched = await panos_client.fetch(
                    row.address, row.port, credentials,
                    verify_tls=row.verify_tls,
                )
            elif row.vendor == "f5":
                fetched = await f5_client.fetch(
                    row.address, row.port, credentials,
                    verify_tls=row.verify_tls,
                )
            else:
                raise ValueError(f"unsupported vendor: {row.vendor}")
        except (panos_client.PanosAuthError, f5_client.F5AuthError) as exc:
            await _set_status(db, device_id, "auth_failed", str(exc))
            await db.commit()
            return {"device_id": str(device_id), "ok": False,
                    "error": "auth_failed", "detail": str(exc)}
        except (panos_client.PanosFetchError, f5_client.F5FetchError) as exc:
            await _set_status(db, device_id, "unreachable", str(exc))
            await db.commit()
            return {"device_id": str(device_id), "ok": False,
                    "error": "unreachable", "detail": str(exc)}
        except Exception as exc:                                    # noqa: BLE001
            log.exception("unexpected fetch failure for %s", device_id)
            await _set_status(db, device_id, "unreachable",
                              f"unexpected: {exc}")
            await db.commit()
            return {"device_id": str(device_id), "ok": False,
                    "error": "unexpected", "detail": str(exc)}

        sha = hashlib.sha256(fetched.config_bytes).hexdigest()
        is_edge = detect_edge_role(fetched.config_bytes, row.vendor)

        if sha == row.last_config_sha256:
            # No change — just bump last_polled_at + status.
            await _set_status(db, device_id, "ok", None,
                              is_edge=is_edge)
            await db.commit()
            return {"device_id": str(device_id), "ok": True,
                    "changed": False, "sha256": sha}

        # Persist the new config bytes to disk
        upload_id = uuid.uuid4()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        device_subdir = config_dir / f"device-{row.id}"
        device_subdir.mkdir(parents=True, exist_ok=True)
        filename = f"{row.hostname}-{timestamp}.{fetched.extension}"
        stored_path = device_subdir / f"{upload_id}-{filename}"
        stored_path.write_bytes(fetched.config_bytes)

        role = "firewall" if row.vendor in ("panos", "fortinet") else "loadbalancer"
        await db.execute(sa.text("""
            INSERT INTO topology_config_uploads (
                id, vendor, role, hostname, original_filename, sha256,
                size_bytes, stored_path, parse_status, source, device_uuid
            ) VALUES (
                :id, :v, :r, :h, :fn, :sha, :sz, :sp, 'pending', 'scheduler', :duuid
            )
        """), {
            "id": str(upload_id), "v": row.vendor, "r": role, "h": row.hostname,
            "fn": filename, "sha": sha, "sz": len(fetched.config_bytes),
            "sp": str(stored_path), "duuid": str(row.id),
        })

        await db.execute(sa.text("""
            UPDATE topology_devices SET
                last_polled_at      = NOW(),
                last_status         = 'ok',
                last_error          = NULL,
                last_config_sha256  = :sha,
                last_upload_id      = :uid,
                is_edge             = :edge
            WHERE id = :id
        """), {"sha": sha, "uid": str(upload_id),
               "edge": is_edge, "id": str(device_id)})
        await db.commit()

        return {"device_id": str(device_id), "ok": True,
                "changed": True, "sha256": sha,
                "upload_id": str(upload_id)}


async def _set_status(db, device_id: uuid.UUID, status: str,
                      err: Optional[str], *, is_edge: Optional[bool] = None) -> None:
    if is_edge is None:
        await db.execute(sa.text("""
            UPDATE topology_devices SET
                last_polled_at = NOW(),
                last_status    = :s::topology_device_status,
                last_error     = :e
            WHERE id = :id
        """), {"s": status, "e": err, "id": str(device_id)})
    else:
        await db.execute(sa.text("""
            UPDATE topology_devices SET
                last_polled_at = NOW(),
                last_status    = :s::topology_device_status,
                last_error     = :e,
                is_edge        = :edge
            WHERE id = :id
        """), {"s": status, "e": err, "edge": is_edge,
               "id": str(device_id)})
