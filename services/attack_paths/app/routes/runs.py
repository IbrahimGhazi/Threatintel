"""
Internal endpoints for run orchestration. Called by the api service.

POST /internal/runs        — trigger an analysis run on uploaded configs
GET  /internal/runs/{id}   — current status (mirror of Postgres row)
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.auth import require_api_key
from app.engine.orchestrator import RunOrchestrator

log = logging.getLogger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])


class TriggerRunIn(BaseModel):
    upload_ids: List[uuid.UUID]
    triggered_by: Optional[str] = None


class TriggerRunOut(BaseModel):
    run_id: uuid.UUID
    status: str


@router.post("/runs", response_model=TriggerRunOut, dependencies=[Depends(require_api_key)])
async def trigger_run(payload: TriggerRunIn) -> TriggerRunOut:
    if not payload.upload_ids:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="upload_ids must be non-empty")

    orchestrator = RunOrchestrator()
    run_id = await orchestrator.create_run(
        upload_ids=payload.upload_ids,
        triggered_by=payload.triggered_by,
    )
    # Fire-and-forget: run executes in the background; Postgres is the
    # source of truth for status. The api service polls.
    asyncio.create_task(orchestrator.execute(run_id))
    return TriggerRunOut(run_id=run_id, status="pending")


@router.get("/runs/{run_id}", dependencies=[Depends(require_api_key)])
async def get_run(run_id: uuid.UUID):
    orchestrator = RunOrchestrator()
    row = await orchestrator.get_run(run_id)
    if not row:
        raise HTTPException(status_code=404, detail="run not found")
    return row
