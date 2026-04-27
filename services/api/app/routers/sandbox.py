"""
Sandbox submission and result retrieval endpoints.
"""
import hashlib
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import asyncio
import json

import aiofiles
from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.middleware.auth import require_api_key
from app.models.sandbox import SandboxResult

logger = logging.getLogger(__name__)


async def _require_key_header_or_query(
    request: Request,
    api_key: Optional[str] = Query(None, alias="api_key"),
) -> str:
    """Accept API key from X-API-Key header OR ?api_key= query param (needed for EventSource)."""
    settings = get_settings()
    # EventSource cannot set custom headers, so fall back to query param
    key = request.headers.get("x-api-key") or api_key
    if not key or key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key.",
        )
    return key

SANDBOX_FILES_DIR = os.environ.get("SANDBOX_FILES_DIR", "/sandbox-files")

# Stage definitions — must match engines/local/progress.py STAGES.
_PENDING_STAGES = [
    {"id": "file_received",     "label": "File Received",            "status": "pending", "started_at": None, "duration_ms": None},
    {"id": "queued",            "label": "Queue Waiting",            "status": "pending", "started_at": None, "duration_ms": None},
    {"id": "static_analysis",   "label": "Static Analysis",          "status": "pending", "started_at": None, "duration_ms": None},
    {"id": "sandbox_prep",      "label": "Sandbox Preparation",      "status": "pending", "started_at": None, "duration_ms": None},
    {"id": "behavioral_exec",   "label": "Behavioral Execution",     "status": "pending", "started_at": None, "duration_ms": None},
    {"id": "time_manipulation", "label": "Time-Manipulation Tests",  "status": "pending", "started_at": None, "duration_ms": None},
    {"id": "ioc_extraction",    "label": "IOC Extraction",           "status": "pending", "started_at": None, "duration_ms": None},
    {"id": "report_generation", "label": "Report Generation",        "status": "pending", "started_at": None, "duration_ms": None},
]


async def _seed_queued_progress(sha256: str, redis_url: str) -> None:
    """
    Write a fresh 'queued' progress snapshot to Redis immediately when a job
    is submitted or re-queued.  This overwrites any stale 'completed' data
    from a previous run so the SSE stream doesn't close before the new
    analysis has a chance to start.
    """
    now = datetime.now(timezone.utc).isoformat()
    payload = json.dumps({
        "sha256":            sha256,
        "overall_status":    "queued",
        "current_stage":     None,
        "completed_stages":  [],
        "stages":            _PENDING_STAGES,
        "started_at":        now,
        "updated_at":        now,
        "error":             "",
    })
    try:
        import redis.asyncio as aioredis
        r = aioredis.from_url(redis_url, decode_responses=True)
        await r.setex(f"sandbox:progress:{sha256}", 3600, payload)
        await r.aclose()
    except Exception as exc:
        logger.warning("Could not seed progress Redis for %s: %s", sha256[:16], exc)


router = APIRouter(prefix="/sandbox", tags=["Sandbox"])


class SandboxResultOut(BaseModel):
    id: uuid.UUID
    file_sha256: str
    file_name: Optional[str]
    file_size: Optional[int]
    file_type: Optional[str]
    status: str
    verdict: Optional[str]
    malware_score: Optional[int]
    malware_family: Optional[str]
    sandbox_engine: str
    extracted_iocs: Dict[str, Any]
    submitted_at: Any
    completed_at: Optional[Any]
    error: Optional[str]

    class Config:
        from_attributes = True


@router.post("/submit", status_code=status.HTTP_202_ACCEPTED)
async def submit_file(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """
    Upload a file for sandbox analysis.
    Files are hashed; if the hash is already known, the existing result is returned.
    """
    settings = get_settings()
    if not settings.sandbox_enabled:
        raise HTTPException(
            status_code=503,
            detail="Sandbox integration is not enabled. Set SANDBOX_ENABLED=true.",
        )

    # Read file content and compute hashes
    content = await file.read()
    if len(content) > 50 * 1024 * 1024:  # 50MB limit
        raise HTTPException(status_code=413, detail="File too large (max 50MB)")

    sha256 = hashlib.sha256(content).hexdigest()
    sha1 = hashlib.sha1(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()

    # Check if already submitted
    existing = (
        await db.execute(select(SandboxResult).where(SandboxResult.file_sha256 == sha256))
    ).scalar_one_or_none()

    if existing:
        # If already completed/failed, just return the cached result.
        # If still pending or running, re-publish to NATS in case the previous
        # message was lost or the worker crashed mid-analysis.
        if existing.status in ("pending", "running"):
            logger.warning("Re-publishing stuck %s job: result_id=%s sha256=%s", existing.status, existing.id, sha256[:16])
            # Reset to pending so the worker processes it cleanly
            if existing.status == "running":
                await db.execute(
                    text("UPDATE sandbox_results SET status = 'pending', started_at = NULL WHERE id = CAST(:rid AS uuid)"),
                    {"rid": str(existing.id)},
                )
                await db.commit()
            import orjson as _orjson
            _nc = getattr(request.app.state, "nats_client", None)
            if _nc:
                try:
                    await _nc.publish("ti.sandbox.submit", _orjson.dumps({
                        "result_id": str(existing.id),
                        "sha256": sha256,
                        "file_name": file.filename,
                    }))
                    logger.info("Re-published stuck job to NATS: result_id=%s", existing.id)
                    # Reset Redis progress so the SSE doesn't see stale completed data.
                    _redis_url = os.environ.get("SANDBOX_PROGRESS_REDIS_URL", settings.redis_url)
                    await _seed_queued_progress(sha256, _redis_url)
                except Exception as exc:
                    logger.error("Re-publish failed: %s", exc)
            else:
                logger.error("NATS unavailable for re-publish: result_id=%s", existing.id)
        return {
            "id": str(existing.id),
            "sha256": sha256,
            "status": "pending" if existing.status in ("pending", "running") else existing.status,
            "verdict": existing.verdict,
            "message": "File previously submitted" if existing.status not in ("pending", "running") else "Re-queued for analysis",
        }

    # Persist file to shared volume so the sandbox worker can read it
    os.makedirs(SANDBOX_FILES_DIR, exist_ok=True)
    file_path = os.path.join(SANDBOX_FILES_DIR, sha256)
    if not os.path.exists(file_path):
        async with aiofiles.open(file_path, "wb") as f:
            await f.write(content)

    # Create pending record
    engine_name = os.environ.get("SANDBOX_ENGINE", "mock")
    result = SandboxResult(
        file_sha256=sha256,
        file_sha1=sha1,
        file_md5=md5,
        file_name=file.filename,
        file_size=len(content),
        status="pending",
        sandbox_engine=engine_name,
    )
    db.add(result)
    await db.flush()
    await db.commit()  # commit before publishing so the worker sees the row

    # Seed Redis with a fresh 'queued' state BEFORE publishing to NATS.
    # This ensures the SSE stream always sees a valid starting state and never
    # gets stale 'completed' data from a previous analysis of the same file.
    _redis_url = os.environ.get("SANDBOX_PROGRESS_REDIS_URL", settings.redis_url)
    await _seed_queued_progress(sha256, _redis_url)

    # Publish to NATS for async processing
    import orjson
    nats_client = getattr(request.app.state, "nats_client", None)
    if nats_client:
        payload = {
            "result_id": str(result.id),
            "sha256": sha256,
            "file_name": file.filename,
        }
        try:
            logger.info("Publishing sandbox job to NATS: result_id=%s sha256=%s", result.id, sha256[:16])
            await nats_client.publish("ti.sandbox.submit", orjson.dumps(payload))
            logger.info("Sandbox job published to NATS: result_id=%s", result.id)
        except Exception as exc:
            logger.error("Failed to publish sandbox job to NATS: result_id=%s error=%s", result.id, exc)
    else:
        logger.error("NATS client unavailable — sandbox job result_id=%s will not be processed", result.id)

    return {
        "id": str(result.id),
        "sha256": sha256,
        "status": "pending",
        "message": "File queued for analysis",
    }


@router.get("", response_model=List[SandboxResultOut])
async def list_results(
    status: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    stmt = select(SandboxResult).order_by(desc(SandboxResult.submitted_at))
    if status:
        stmt = stmt.where(SandboxResult.status == status)
    if verdict:
        stmt = stmt.where(SandboxResult.verdict == verdict)
    stmt = stmt.offset(offset).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return list(rows)


@router.get("/hash/{sha256}", response_model=SandboxResultOut)
async def get_result_by_hash(
    sha256: str,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    row = (
        await db.execute(select(SandboxResult).where(SandboxResult.file_sha256 == sha256.lower()))
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="No sandbox result for this hash")
    return row


@router.get("/{sha256}/progress")
async def sandbox_progress_stream(
    sha256: str,
    _: str = Depends(_require_key_header_or_query),
):
    """
    SSE stream of sandbox analysis progress.
    Polls Redis for stage updates and streams them until analysis completes.
    Accepts API key via X-API-Key header OR ?api_key= query param (EventSource compatibility).
    """
    settings = get_settings()
    # Sandbox progress is written by the sandbox service; use its Redis URL if provided,
    # otherwise fall back to the API's own Redis URL.
    progress_redis_url = os.environ.get("SANDBOX_PROGRESS_REDIS_URL", settings.redis_url)

    async def event_stream():
        try:
            import redis.asyncio as aioredis  # type: ignore
            r = aioredis.from_url(progress_redis_url, decode_responses=True)
            for _ in range(1200):   # max 10 min @ 500ms polls
                data = await r.get(f"sandbox:progress:{sha256}")
                if data:
                    yield f"data: {data}\n\n"
                    try:
                        parsed = json.loads(data)
                        if parsed.get("overall_status") in ("completed", "failed"):
                            break
                    except Exception:
                        pass
                else:
                    # No Redis key yet — emit a queued placeholder
                    yield f"data: {json.dumps({'overall_status': 'queued', 'stages': [], 'sha256': sha256})}\n\n"
                await asyncio.sleep(0.5)
            await r.aclose()
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/{sha256}/requeue", status_code=200)
async def requeue_analysis(
    sha256: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    """
    Re-queue a stuck pending or running sandbox analysis.
    Resets the DB status to 'pending', re-seeds Redis, and re-publishes to NATS.
    Called automatically by the frontend after 60 s with no progress.
    """
    row = (
        await db.execute(
            select(SandboxResult).where(SandboxResult.file_sha256 == sha256.lower())
        )
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="No sandbox result for this hash")

    if row.status not in ("pending", "running"):
        return {"status": row.status, "requeued": False, "message": f"Analysis already {row.status}"}

    # Reset to pending so the worker will process it again
    await db.execute(
        text("UPDATE sandbox_results SET status = 'pending', started_at = NULL WHERE file_sha256 = :sha256"),
        {"sha256": sha256.lower()},
    )
    await db.commit()

    # Re-seed Redis so the SSE stream shows queued (not stale completed data)
    settings = get_settings()
    redis_url = os.environ.get("SANDBOX_PROGRESS_REDIS_URL", settings.redis_url)
    await _seed_queued_progress(sha256, redis_url)

    # Re-publish to NATS
    import orjson as _orjson
    nats_client = getattr(request.app.state, "nats_client", None)
    if not nats_client:
        raise HTTPException(status_code=503, detail="NATS unavailable — worker cannot receive job")
    try:
        await nats_client.publish("ti.sandbox.submit", _orjson.dumps({
            "result_id": str(row.id),
            "sha256":    sha256.lower(),
            "file_name": row.file_name,
        }))
        logger.info("Requeued sandbox job: result_id=%s sha256=%s", row.id, sha256[:16])
    except Exception as exc:
        logger.error("Requeue NATS publish failed: result_id=%s error=%s", row.id, exc)
        raise HTTPException(status_code=500, detail="Failed to re-publish job to NATS")

    return {"status": "pending", "requeued": True, "message": "Analysis re-queued successfully"}


@router.get("/{result_id}", response_model=SandboxResultOut)
async def get_result(
    result_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: str = Depends(require_api_key),
):
    row = (
        await db.execute(select(SandboxResult).where(SandboxResult.id == result_id))
    ).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Sandbox result not found")
    return row
