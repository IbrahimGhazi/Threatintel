"""
Sandbox progress emitter — writes per-stage status to Redis so the
API can stream it to the browser via SSE.

Uses synchronous Redis so it can be called from both async coroutines
(via run_in_executor) and the blocking thread inside DynamicAnalyzer.
"""
import json
import logging
import os
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

REDIS_URL = os.getenv("SANDBOX_PROGRESS_REDIS_URL") or os.getenv("REDIS_URL", "redis://localhost:6379/0")

STAGES = OrderedDict([
    ("file_received",    "File Received"),
    ("queued",           "Queue Waiting"),
    ("static_analysis",  "Static Analysis"),
    ("sandbox_prep",     "Sandbox Preparation"),
    ("behavioral_exec",  "Behavioral Execution"),
    ("time_manipulation","Time-Manipulation Tests"),
    ("ioc_extraction",   "IOC Extraction"),
    ("report_generation","Report Generation"),
])


class ProgressEmitter:
    """Thread-safe progress tracker that writes to Redis."""

    def __init__(self, sha256: str):
        self.sha256      = sha256
        self._overall    = "running"
        self._error      = ""
        self._started    = time.time()
        self._stage_start: Optional[float] = None

        self._stages = OrderedDict(
            (sid, {
                "id":          sid,
                "label":       label,
                "status":      "pending",
                "started_at":  None,
                "duration_ms": None,
            })
            for sid, label in STAGES.items()
        )

    # ── Public API (synchronous, safe from any thread) ─────────────────────

    def mark_running(self, stage_id: str) -> None:
        self._stage_start = time.time()
        s = self._stages[stage_id]
        s["status"]     = "running"
        s["started_at"] = _now()
        self._push()

    def mark_done(self, stage_id: str) -> None:
        s = self._stages[stage_id]
        s["status"] = "done"
        if self._stage_start:
            s["duration_ms"] = int((time.time() - self._stage_start) * 1000)
        self._push()

    def mark_skipped(self, stage_id: str) -> None:
        self._stages[stage_id]["status"] = "skipped"
        self._push()

    def mark_complete(self) -> None:
        self._overall = "completed"
        # mark anything still pending/running as done
        for s in self._stages.values():
            if s["status"] in ("pending", "running"):
                s["status"] = "done"
        self._push()

    def mark_failed(self, error: str = "") -> None:
        self._overall = "failed"
        self._error   = error
        for s in self._stages.values():
            if s["status"] == "running":
                s["status"] = "failed"
        self._push()

    def touch(self) -> None:
        """Heartbeat – re-push current state with a fresh updated_at timestamp."""
        self._push()

    # ── Internal ───────────────────────────────────────────────────────────

    def _push(self) -> None:
        stages_list = list(self._stages.values())
        current_stage = next(
            (s["id"] for s in stages_list if s["status"] == "running"), None
        )
        completed_stages = [s["id"] for s in stages_list if s["status"] == "done"]

        payload = json.dumps({
            "sha256":            self.sha256,
            "overall_status":    self._overall,
            "current_stage":     current_stage,
            "completed_stages":  completed_stages,
            "stages":            stages_list,
            "started_at":        datetime.fromtimestamp(self._started, tz=timezone.utc).isoformat(),
            "updated_at":        _now(),
            "error":             self._error,
        })
        try:
            import redis as sync_redis  # type: ignore
            r = sync_redis.from_url(REDIS_URL, socket_connect_timeout=2)
            r.setex(f"sandbox:progress:{self.sha256}", 3600, payload)
            r.close()
        except Exception as exc:
            log.warning("ProgressEmitter Redis write failed: %s", exc)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
