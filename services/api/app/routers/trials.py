"""Internal "Generate Trial OVA" admin endpoints.

Wraps tools/ova-builder/build-trial-ova.sh in a long-running async
subprocess.  Progress is parsed line-by-line from the script's stdout
and persisted to a `trial_builds` table so the frontend can poll for
status without holding an SSE connection through the multi-minute
qcow2→VMDK conversion.

Routes:
  POST /admin/trials/build           start a build
  GET  /admin/trials                 list recent builds (most recent first)
  GET  /admin/trials/{job_id}        poll status of a single build
  GET  /admin/trials/{job_id}/download   download the .ova file
  DELETE /admin/trials/{job_id}      delete a build (frees disk)

Configuration (env vars on the ti-api pod):
  OVA_BUILDER_PATH    path to build-trial-ova.sh
                      (default: /app/tools/ova-builder/build-trial-ova.sh)
  OVA_BUILDER_CWD     working directory for the build (default: alongside script)
  OVA_GOLDEN_DISK     path to ti-platform-golden.qcow2
                      (default: /opt/ti-platform/golden/golden.qcow2)
  OVA_DIST_DIR        where built .ova files land
                      (default: /var/lib/ti-platform/trial-builds)
  OVA_BUILD_TTL_DAYS  cleanup threshold (default: 14)

Auth: every route requires the platform's API key (existing
`require_api_key` dep).  The frontend gates the UI itself with
NEXT_PUBLIC_ADMIN_UI; this is the second layer (API can refuse if the
flag is wrong).  No role-based gating yet — there's no user system.
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status as http_status
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db, AsyncSessionLocal
from app.middleware.auth import require_api_key

# ── Download-specific auth ───────────────────────────────────────────────────
# Browser <a href="…/download"> clicks can't attach the X-API-Key header
# the way `apiFetch()` does, so the download route also accepts an
# `?api_key=` query parameter.  Other routes still use the strict
# header-only `require_api_key` from app.middleware.auth.
_DOWNLOAD_API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key_or_query(
    header_key: Optional[str] = Depends(_DOWNLOAD_API_KEY_HEADER),
    query_key:  Optional[str] = Query(None, alias="api_key", include_in_schema=False),
) -> str:
    expected = get_settings().api_key
    presented = header_key or query_key or ""
    if not presented or presented != expected:
        raise HTTPException(
            status_code=http_status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing API key (header X-API-Key or query ?api_key=).",
        )
    return presented

log = logging.getLogger("ti.api")

router = APIRouter(prefix="/admin/trials", tags=["trials"])


# ── Canonical modular-OVA feature set ────────────────────────────────────────
# Operator-toggleable features the OVA builder honours.  Anything not in
# this set is "always-on" — we don't expose it through the build UI.
# Keep in sync with:
#   tools/ova-builder/build-trial-ova.sh:CANONICAL_FEATURES
#   tools/ova-builder/packer/files/values-trial-ova.yaml (per-feature `enabled:`)
CANONICAL_FEATURES: tuple[str, ...] = (
    "monitoring",
    "sandbox",
    "icap",
    "correlation",
    "enrichment",
    "vendor_audit",
    "minio",
    "neo4j",
    "attack_paths",
)


def _validate_features(features: list[str]) -> list[str]:
    """Lowercase + dedupe, then validate every entry is in the canonical
    set.  Returns the cleaned list in canonical-set order so callers/log
    lines see a stable representation.  Raises ValueError on the first
    unknown feature so the caller can surface it as HTTP 400.

    The legacy sentinel `"full"` (older CLI/UI clients) is treated as
    "use OVA-baked defaults" — equivalent to passing an empty list.
    """
    cleaned: set[str] = set()
    for raw in features:
        if not isinstance(raw, str):
            raise ValueError(f"feature must be a string, got {type(raw).__name__}")
        f = raw.strip().lower()
        if not f or f == "full":
            continue
        if f not in CANONICAL_FEATURES:
            raise ValueError(
                f"unknown feature {f!r}; must be a subset of "
                f"{list(CANONICAL_FEATURES)}"
            )
        cleaned.add(f)
    return [c for c in CANONICAL_FEATURES if c in cleaned]


# ── Config ────────────────────────────────────────────────────────────────────

OVA_BUILDER_PATH = os.environ.get(
    "OVA_BUILDER_PATH",
    "/app/tools/ova-builder/build-trial-ova.sh",
)
OVA_BUILDER_CWD = os.environ.get(
    "OVA_BUILDER_CWD",
    str(Path(OVA_BUILDER_PATH).parent) if OVA_BUILDER_PATH else "",
)
OVA_GOLDEN_DISK = os.environ.get(
    "OVA_GOLDEN_DISK",
    "/opt/ti-platform/golden/golden.qcow2",
)
OVA_DIST_DIR = os.environ.get(
    "OVA_DIST_DIR",
    "/var/lib/ti-platform/trial-builds",
)
# License signing key — same Ed25519 key the trial OVAs verify against.
# build-trial-ova.sh reads $LICENSE_PRIV_KEY; we read TI_LICENSE_PRIV_KEY
# (the standard env var the rest of the API uses) and pass it through.
OVA_LICENSE_PRIV_KEY = os.environ.get(
    "TI_LICENSE_PRIV_KEY",
    "/etc/ti-platform/license.priv",
)
OVA_BUILD_TTL_DAYS = int(os.environ.get("OVA_BUILD_TTL_DAYS", "14"))

# Rough script-stage → percent mapping (matches build-trial-ova.sh banners).
# Stage 4 (qcow2→VMDK convert) is the bulk of the wall-clock — we hold
# at 40% across that span and let qemu-img's own progress lines bump it.
# `[ova-builder]`-prefixed phase-1 lines come from the May-2026 stage
# steps (image import + helm phase-1 ordering); they bump us 1→3% before
# step 1 fires so the bar isn't stuck at 0% during the slow image copy.
_STAGE_PROGRESS: list[tuple[str, int]] = [
    ("[ova-builder] ── 0. stage service images", 1),
    ("[ova-builder] ── 0.5. phase-1",            3),
    ("── 1. mint license",         5),
    ("── 2. linked-clone",         15),
    ("── 3. inject license",       25),
    ("── 4. convert qcow2",        35),
    ("── 5. render OVF",           80),
    ("── 6. manifest",             85),
    ("── 7. pack OVA",             90),
    ("Built:",                     100),
]
_QEMU_PROGRESS_RE = re.compile(r"\((\d+(?:\.\d+)?)/100%\)")


# ── Schema (idempotent boot migration) ───────────────────────────────────────

# Split for asyncpg: each prepared statement carries one SQL command.
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS trial_builds (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer      TEXT NOT NULL,
    days          INT  NOT NULL CHECK (days IN (15, 30, 45)),
    features      JSONB NOT NULL DEFAULT '["full"]'::jsonb,
    status        TEXT NOT NULL DEFAULT 'queued',
    progress      INT  NOT NULL DEFAULT 0,
    last_line     TEXT,
    error         TEXT,
    license_id    TEXT,
    ova_filename  TEXT,
    ova_size      BIGINT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ
)
"""
_CREATE_IDX_CREATED_SQL = (
    "CREATE INDEX IF NOT EXISTS trial_builds_created_at_idx "
    "ON trial_builds (created_at DESC)"
)
_CREATE_IDX_STATUS_SQL = (
    "CREATE INDEX IF NOT EXISTS trial_builds_status_idx "
    "ON trial_builds (status) WHERE status IN ('queued','building')"
)


async def ensure_schema() -> None:
    """Idempotent — called from app lifespan."""
    async with AsyncSessionLocal() as db:
        await db.execute(text(_CREATE_TABLE_SQL))
        await db.execute(text(_CREATE_IDX_CREATED_SQL))
        await db.execute(text(_CREATE_IDX_STATUS_SQL))
        await db.commit()


# ── DTOs ─────────────────────────────────────────────────────────────────────

class TrialBuildRequest(BaseModel):
    customer: str = Field(..., min_length=1, max_length=200,
                          description='e.g. "ACME Corp <eval@acme.com>"')
    # `duration_days` is the field name the admin UI sends; `days` is the
    # legacy short form kept for back-compat (CLI scripts, older clients).
    days:          Optional[int] = Field(None, description="Trial length: 15, 30, or 45")
    duration_days: Optional[int] = Field(None, description="Alias for `days`")
    # Modular feature subset.  Empty list / None means "use defaults
    # baked into values-trial-ova.yaml".  Otherwise must be a subset of
    # CANONICAL_FEATURES.
    features: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}

    def resolved_days(self) -> int:
        return self.duration_days if self.duration_days is not None else (self.days or 30)


class TrialBuildOut(BaseModel):
    id:           str
    customer:     str
    days:         int
    features:     list[str]
    status:       str            # queued | building | completed | failed
    progress:     int            # 0-100
    last_line:    Optional[str] = None
    error:        Optional[str] = None
    license_id:   Optional[str] = None
    ova_filename: Optional[str] = None
    ova_size:     Optional[int] = None
    created_at:   datetime
    started_at:   Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expires_at:   Optional[datetime] = None


def _row_to_out(r) -> TrialBuildOut:
    m = dict(r._mapping)
    return TrialBuildOut(
        id=str(m["id"]),
        customer=m["customer"],
        days=m["days"],
        features=list(m.get("features") or []),
        status=m["status"],
        progress=m["progress"] or 0,
        last_line=m.get("last_line"),
        error=m.get("error"),
        license_id=m.get("license_id"),
        ova_filename=m.get("ova_filename"),
        ova_size=m.get("ova_size"),
        created_at=m["created_at"],
        started_at=m.get("started_at"),
        completed_at=m.get("completed_at"),
        expires_at=m.get("expires_at"),
    )


# ── Routes ───────────────────────────────────────────────────────────────────

@router.post("/build", response_model=TrialBuildOut, status_code=202)
async def start_build(
    body: TrialBuildRequest,
    bg:   BackgroundTasks,
    db:   AsyncSession = Depends(get_db),
    _:    str          = Depends(require_api_key),
) -> TrialBuildOut:
    """Start a build.  Returns immediately with the job id; poll GET to track.

    The request body's `features` field must be a subset of the canonical
    modular-OVA feature set (see CANONICAL_FEATURES at the top of this
    module).  Validated features are persisted to `trial_builds.features`
    and translated to `--features f1,f2,...` on the build script CLI;
    enforcement at runtime in the licensing JWT is a separate effort.
    """
    days = body.resolved_days()
    if days not in (15, 30, 45):
        raise HTTPException(400, "trial_build: days must be 15, 30, or 45")
    if not body.customer.strip():
        raise HTTPException(400, "trial_build: customer must not be empty")

    try:
        validated_features = _validate_features(body.features or [])
    except ValueError as exc:
        log.warning("trial_build: rejected features=%r: %s", body.features, exc)
        raise HTTPException(400, f"trial_build: {exc}") from None

    if not Path(OVA_BUILDER_PATH).is_file():
        log.error("trial_build: OVA builder not found: %s", OVA_BUILDER_PATH)
        raise HTTPException(503, {
            "error":   "builder_unavailable",
            "message": f"build-trial-ova.sh not found at {OVA_BUILDER_PATH}. "
                       "Make sure the OVA-builder tools are mounted into the API pod.",
        })
    if not Path(OVA_GOLDEN_DISK).is_file():
        log.error("trial_build: Golden disk not found: %s", OVA_GOLDEN_DISK)
        raise HTTPException(503, {
            "error":   "golden_disk_missing",
            "message": f"Golden disk not found at {OVA_GOLDEN_DISK}. "
                       "Run packer/build.sh on the build host first.",
        })

    job_id = uuid.uuid4()
    expires_at = datetime.now(timezone.utc) + timedelta(days=OVA_BUILD_TTL_DAYS)

    await db.execute(text("""
        INSERT INTO trial_builds (id, customer, days, features, status, expires_at)
        VALUES (:id, :customer, :days, CAST(:features AS jsonb), 'queued', :expires_at)
    """), {
        "id":         str(job_id),
        "customer":   body.customer,
        "days":       days,
        # When the operator passes an empty features list we persist
        # ["full"] (legacy sentinel for "use baked-in defaults"); a
        # validated subset persists exactly as given.
        "features":   _json_dumps(validated_features or ["full"]),
        "expires_at": expires_at,
    })
    await db.commit()

    bg.add_task(_run_build, str(job_id), body.customer, days, validated_features)

    log.info("trial_build: queued id=%s customer=%s days=%d features=%s",
             str(job_id)[:8], body.customer, days, validated_features or ["(defaults)"])
    return await _fetch_one(db, str(job_id))


@router.get("", response_model=list[TrialBuildOut])
async def list_builds(
    limit: int = 50,
    db:    AsyncSession = Depends(get_db),
    _:     str          = Depends(require_api_key),
) -> list[TrialBuildOut]:
    """Most recent builds first.  Excludes deleted rows."""
    if limit < 1 or limit > 200:
        raise HTTPException(400, "limit must be in [1, 200]")
    rows = (await db.execute(text("""
        SELECT * FROM trial_builds
        ORDER BY created_at DESC
        LIMIT :limit
    """), {"limit": limit})).fetchall()
    return [_row_to_out(r) for r in rows]


@router.get("/{job_id}", response_model=TrialBuildOut)
async def get_build(
    job_id: str,
    db:     AsyncSession = Depends(get_db),
    _:      str          = Depends(require_api_key),
) -> TrialBuildOut:
    return await _fetch_one(db, job_id)


@router.get("/{job_id}/download")
async def download_build(
    job_id: str,
    _:      str = Depends(require_api_key_or_query),
):
    async with AsyncSessionLocal() as db:
        out = await _fetch_one(db, job_id)
    if out.status != "completed":
        raise HTTPException(409, {
            "error":   "not_ready",
            "status":  out.status,
            "message": f"build is in status '{out.status}', not yet downloadable",
        })
    if not out.ova_filename:
        raise HTTPException(500, "build completed without an ova_filename — internal error")
    path = Path(OVA_DIST_DIR) / out.ova_filename
    if not path.is_file():
        raise HTTPException(410, {
            "error":   "file_missing",
            "message": f"OVA file no longer on disk at {path} — possibly TTL-cleaned. "
                       "Re-run the build to regenerate.",
        })
    return FileResponse(
        str(path),
        media_type="application/x-virtualbox-ova",
        filename=out.ova_filename,
    )


@router.delete("/{job_id}", status_code=204)
async def delete_build(
    job_id: str,
    db:     AsyncSession = Depends(get_db),
    _:      str          = Depends(require_api_key),
):
    out = await _fetch_one(db, job_id)
    if out.status == "building":
        raise HTTPException(409, "cannot delete a build that's still running")
    if out.ova_filename:
        f = Path(OVA_DIST_DIR) / out.ova_filename
        if f.is_file():
            try:
                f.unlink()
            except OSError as exc:
                log.warning("could not delete %s: %s", f, exc)
    await db.execute(text("DELETE FROM trial_builds WHERE id = :id"),
                     {"id": job_id})
    await db.commit()


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _fetch_one(db: AsyncSession, job_id: str) -> TrialBuildOut:
    row = (await db.execute(text("""
        SELECT * FROM trial_builds WHERE id = :id
    """), {"id": job_id})).fetchone()
    if not row:
        raise HTTPException(404, "build not found")
    return _row_to_out(row)


def _json_dumps(v) -> str:
    import json
    return json.dumps(v)


# ── Background worker ────────────────────────────────────────────────────────

async def _run_build(job_id: str, customer: str, days: int, features: list[str]) -> None:
    """Spawn build-trial-ova.sh and stream progress into the DB row.

    Runs as a FastAPI BackgroundTask so the HTTP request that started it
    has already returned.  Errors are caught and persisted to the row's
    `error` field — never surface back as HTTP responses.

    `features` is the validated modular subset (see CANONICAL_FEATURES);
    when non-empty it is passed as `--features f1,f2,...` to the script.
    """
    log.info("trial_build: [%s] worker starting features=%s",
             job_id[:8], features or ["(defaults)"])

    # Mark started
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            UPDATE trial_builds
               SET status     = 'building',
                   started_at = NOW()
             WHERE id = :id
        """), {"id": job_id})
        await db.commit()

    Path(OVA_DIST_DIR).mkdir(parents=True, exist_ok=True)

    cmd = ["bash", OVA_BUILDER_PATH, customer, str(days)]
    if features:
        cmd += ["--features", ",".join(features)]
    env = {
        **os.environ,
        "DIST_DIR":         OVA_DIST_DIR,
        "GOLDEN_DISK":      OVA_GOLDEN_DISK,
        "LICENSE_PRIV_KEY": OVA_LICENSE_PRIV_KEY,
        # FEATURES env still drives the LICENSE JWT's `features` field
        # (semantic only — runtime enforcement is a separate effort).
        # The CLI --features flag (above) is what drives the helm
        # --set enabled flags inside the OVA at firstboot.
        "FEATURES":         ",".join(features) if features else "full",
        # Stage steps that fold in the May-2026 .tmp/ hotfix scripts.
        # build-trial-ova.sh treats both as opt-in (default "0") so local
        # repo runs aren't slowed by k3d round-trips they don't need.
        "STAGE_IMAGES":     os.environ.get("OVA_STAGE_IMAGES", "1"),
        "STAGE_PHASE1":     os.environ.get("OVA_STAGE_PHASE1", "1"),
        "K3D_CLUSTER":      os.environ.get("OVA_K3D_CLUSTER", "ti-k8s"),
        # libguestfs/virt-customize need a writable /tmp inside the pod —
        # /var/tmp is read-only when running as UID 10001.  Belt + braces:
        # build-trial-ova.sh sets these too, but the script's defaults
        # only apply if these aren't already in the environment.
        "TMPDIR":           os.environ.get("TMPDIR", "/tmp"),
        # Force unbuffered output so we can stream progress live.
        "PYTHONUNBUFFERED": "1",
    }

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=OVA_BUILDER_CWD or None,
            env=env,
        )
    except FileNotFoundError as exc:
        await _mark_failed(job_id, f"could not exec builder: {exc}")
        return

    last_db_write = 0.0
    progress      = 0
    license_id    = None
    last_line     = ""

    assert proc.stdout is not None  # for typecheck
    async for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip()
        last_line = line[:500]

        # Stage banners → coarse progress
        for marker, pct in _STAGE_PROGRESS:
            if marker in line:
                progress = max(progress, pct)
                break

        # qemu-img convert prints "(NN.NN/100%)" lines we can map onto
        # the 35→80 stage range to give the user a smooth progress bar
        # during the slowest part of the build.
        m = _QEMU_PROGRESS_RE.search(line)
        if m and 35 <= progress < 80:
            try:
                pct = float(m.group(1))
                progress = 35 + int(pct * 0.45)   # 35 → 80
            except ValueError:
                pass

        # Capture license id from the header (line starts: "[license-gen] issued: …")
        if license_id is None and "[license-gen] issued:" in line:
            license_id = line.split("issued:", 1)[1].strip().split()[0]

        # Throttle DB writes to ~2/sec
        now = time.time()
        if now - last_db_write > 0.5:
            await _update_progress(job_id, progress, last_line, license_id)
            last_db_write = now

    rc = await proc.wait()

    if rc == 0:
        # find newest .ova in DIST_DIR for this customer slug
        slug = _slugify(customer)
        candidates = sorted(
            Path(OVA_DIST_DIR).glob(f"ti-platform-trial-{slug}-{days}d*.ova"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            await _mark_failed(job_id,
                f"build script exited 0 but no .ova found for slug={slug} days={days}")
            return
        ova = candidates[0]
        size = ova.stat().st_size
        await _mark_completed(job_id, ova.name, size, license_id, last_line)
    else:
        await _mark_failed(job_id, f"build script exited {rc}.  last line: {last_line}")


async def _update_progress(job_id: str, progress: int, last_line: str,
                           license_id: Optional[str]) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            UPDATE trial_builds
               SET progress   = GREATEST(progress, :p),
                   last_line  = :ll,
                   license_id = COALESCE(license_id, :lid)
             WHERE id = :id
        """), {"id": job_id, "p": progress, "ll": last_line, "lid": license_id})
        await db.commit()


async def _mark_completed(job_id: str, filename: str, size: int,
                          license_id: Optional[str], last_line: str) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            UPDATE trial_builds
               SET status       = 'completed',
                   progress     = 100,
                   ova_filename = :fn,
                   ova_size     = :sz,
                   license_id   = COALESCE(license_id, :lid),
                   last_line    = :ll,
                   completed_at = NOW()
             WHERE id = :id
        """), {"id": job_id, "fn": filename, "sz": size,
               "lid": license_id, "ll": last_line})
        await db.commit()
    log.info("[%s] build completed: %s (%d bytes)", job_id[:8], filename, size)


async def _mark_failed(job_id: str, error: str) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            UPDATE trial_builds
               SET status       = 'failed',
                   error        = :err,
                   completed_at = NOW()
             WHERE id = :id
        """), {"id": job_id, "err": error[:2000]})
        await db.commit()
    log.warning("[%s] build failed: %s", job_id[:8], error[:200])


def _slugify(customer: str) -> str:
    """Mirror the slugify in build-trial-ova.sh — lowercase alnum + hyphens, max 40."""
    s = re.sub(r"<[^>]*>", "", customer)
    s = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").lower()
    return s[:40]


# ── TTL cleanup loop ─────────────────────────────────────────────────────────

async def cleanup_loop() -> None:
    """Periodically delete OVAs past their TTL.  Runs every 6 h."""
    while True:
        try:
            await _cleanup_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("trial-build cleanup error: %s", exc)
        await asyncio.sleep(6 * 3600)


async def _cleanup_once() -> None:
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(text("""
            SELECT id, ova_filename FROM trial_builds
             WHERE expires_at IS NOT NULL
               AND expires_at < NOW()
        """))).fetchall()
    if not rows:
        return
    log.info("trial-build cleanup: %d expired build(s)", len(rows))
    for r in rows:
        m = dict(r._mapping)
        if m.get("ova_filename"):
            f = Path(OVA_DIST_DIR) / m["ova_filename"]
            if f.is_file():
                try:
                    f.unlink()
                except OSError as exc:
                    log.warning("could not delete %s: %s", f, exc)
        async with AsyncSessionLocal() as db:
            await db.execute(text("DELETE FROM trial_builds WHERE id = :id"),
                             {"id": str(m["id"])})
            await db.commit()


def start_cleanup_task() -> asyncio.Task:
    return asyncio.create_task(cleanup_loop(), name="trial-build-cleanup")
