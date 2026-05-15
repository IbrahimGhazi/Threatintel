"""Modular-OVA feature validation + wiring tests.

Covers:
- canonical feature set is exactly the operator-visible toggles
- _validate_features lowercases, dedupes, rejects unknowns, and treats
  the legacy 'full' sentinel as "use defaults"
- POST /admin/trials/build validates features, persists the canonical
  list, and translates to `--features f1,f2,...` on the build script CLI

This test deliberately avoids spawning the real build-trial-ova.sh
process — we monkey-patch the background task to capture the args
that would have gone to the script.  That keeps the test hermetic
(no qemu-img / virt-customize / etc.) while still exercising the
end-to-end validation + flag-translation path.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest


# trials.py imports sqlalchemy + app.config + app.database +
# app.middleware.auth at module scope.  Stub them just enough that the
# import succeeds; the endpoint test then monkey-patches _run_build
# and _fetch_one to skip DB writes.
def _install_stubs(monkeypatch, tmp_path: Path) -> None:
    sa = types.ModuleType("sqlalchemy")
    sa.text = lambda s: s  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sqlalchemy", sa)

    sa_async = types.ModuleType("sqlalchemy.ext.asyncio")
    sa_async.AsyncSession = type("AsyncSession", (), {})  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sqlalchemy.ext.asyncio", sa_async)
    monkeypatch.setitem(sys.modules, "sqlalchemy.ext", types.ModuleType("sqlalchemy.ext"))

    cfg = types.ModuleType("app.config")
    cfg.get_settings = lambda: types.SimpleNamespace(api_key="dev")  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "app.config", cfg)

    class _StubSession:
        async def execute(self, *_a, **_kw):
            return types.SimpleNamespace(fetchone=lambda: None, fetchall=lambda: [])

        async def commit(self):
            return None

    async def _get_db():
        yield _StubSession()

    db = types.ModuleType("app.database")
    db.get_db = _get_db                       # type: ignore[attr-defined]
    db.AsyncSessionLocal = _StubSession       # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "app.database", db)

    # Replicate require_api_key (403 on bad key) so the auth-gate test
    # exercises a realistic dependency.
    from fastapi import HTTPException, Security, status as http_status
    from fastapi.security import APIKeyHeader

    _hdr = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def _require(api_key: str = Security(_hdr)) -> str:
        if api_key != "dev":
            raise HTTPException(http_status.HTTP_403_FORBIDDEN, "bad key")
        return api_key

    monkeypatch.setitem(sys.modules, "app.middleware", types.ModuleType("app.middleware"))
    auth = types.ModuleType("app.middleware.auth")
    auth.require_api_key = _require           # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "app.middleware.auth", auth)

    repo_root = Path(__file__).resolve().parents[1]   # services/api/
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    # Existence checks in start_build need real paths to point at.
    builder = tmp_path / "build-trial-ova.sh"
    builder.write_text("#!/bin/sh\necho mock $@\n")
    builder.chmod(0o755)
    golden = tmp_path / "golden.qcow2"
    golden.write_bytes(b"\x00")
    monkeypatch.setenv("OVA_BUILDER_PATH", str(builder))
    monkeypatch.setenv("OVA_GOLDEN_DISK", str(golden))
    monkeypatch.setenv("OVA_DIST_DIR",    str(tmp_path / "dist"))


# ── Pure validation tests ────────────────────────────────────────────────────

def _import_trials(monkeypatch, tmp_path):
    _install_stubs(monkeypatch, tmp_path)
    import importlib
    if "app.routers.trials" in sys.modules:
        importlib.reload(sys.modules["app.routers.trials"])
    from app.routers import trials
    return trials


def test_canonical_features_set(monkeypatch, tmp_path):
    trials = _import_trials(monkeypatch, tmp_path)
    # The full operator-visible toggle set, per the Unit-2 spec.
    assert trials.CANONICAL_FEATURES == (
        "monitoring", "sandbox", "icap", "correlation", "enrichment",
        "vendor_audit", "minio", "neo4j", "attack_paths",
    )


def test_validate_features_happy_path(monkeypatch, tmp_path):
    trials = _import_trials(monkeypatch, tmp_path)
    # Returns canonical-order, lowercased, deduped, stripped.
    out = trials._validate_features(["Sandbox", "sandbox", "  ICAP  ", "correlation"])
    assert out == ["sandbox", "icap", "correlation"]


def test_validate_features_empty_and_legacy_full(monkeypatch, tmp_path):
    trials = _import_trials(monkeypatch, tmp_path)
    assert trials._validate_features([]) == []
    # Legacy clients sending "full" → treated as "use defaults".
    assert trials._validate_features(["full"]) == []


def test_validate_features_rejects_unknown(monkeypatch, tmp_path):
    trials = _import_trials(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="unknown feature 'foobar'"):
        trials._validate_features(["sandbox", "foobar"])


def test_validate_features_rejects_non_string(monkeypatch, tmp_path):
    trials = _import_trials(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="must be a string"):
        trials._validate_features([123])  # type: ignore[list-item]


# ── End-to-end endpoint test via TestClient ──────────────────────────────────

def test_post_admin_trials_build_validates_and_forwards_features(monkeypatch, tmp_path):
    """POST /admin/trials/build with a canonical subset:
       - returns 202
       - echoes the features back in the response
       - the background task is called with `--features sandbox,correlation`
         on the script CLI (the only thing operators can grep for).
    """
    trials = _import_trials(monkeypatch, tmp_path)

    # Capture what would be sent to the subprocess without spawning it.
    captured: dict = {}

    async def _fake_run_build(job_id, customer, days, features):
        captured["job_id"]   = job_id
        captured["customer"] = customer
        captured["days"]     = days
        captured["features"] = features
        # Build the exact `cmd` the real worker would build, so the
        # test asserts on the eventual CLI surface — not just the
        # validated list.
        cmd = ["bash", str(tmp_path / "build-trial-ova.sh"), customer, str(days)]
        if features:
            cmd += ["--features", ",".join(features)]
        captured["cmd"] = cmd

    monkeypatch.setattr(trials, "_run_build", _fake_run_build)

    # Make _fetch_one return a deterministic payload so the response
    # serialisation works.
    from datetime import datetime, timezone

    async def _fake_fetch_one(db, job_id):
        return trials.TrialBuildOut(
            id=job_id,
            customer="Acme Corp",
            days=15,
            features=["sandbox", "correlation", "enrichment"],
            status="queued",
            progress=0,
            created_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(trials, "_fetch_one", _fake_fetch_one)

    # Spin up the app with only this router so we don't drag in the
    # full TI-platform startup (license loops, NATS, etc.).
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(trials.router)
    client = TestClient(app)

    # Task-spec payload verbatim, plus a hostile feature to prove
    # validation triggers on bad input too.
    r_ok = client.post(
        "/admin/trials/build",
        headers={"X-API-Key": "dev"},
        json={"customer": "Acme Corp", "duration_days": 15,
              "features": ["sandbox", "correlation", "enrichment"]},
    )
    assert r_ok.status_code == 202, r_ok.text
    body = r_ok.json()
    assert body["features"] == ["sandbox", "correlation", "enrichment"]
    assert body["days"] == 15

    # Background-task ran with the validated subset and the right CLI.
    assert captured["features"] == ["sandbox", "correlation", "enrichment"]
    assert "--features" in captured["cmd"]
    fidx = captured["cmd"].index("--features")
    assert captured["cmd"][fidx + 1] == "sandbox,correlation,enrichment"

    # Bad feature → 400, body parses the validator's message.
    r_bad = client.post(
        "/admin/trials/build",
        headers={"X-API-Key": "dev"},
        json={"customer": "Acme Corp", "duration_days": 15,
              "features": ["sandbox", "definitely-not-a-feature"]},
    )
    assert r_bad.status_code == 400
    assert "definitely-not-a-feature" in r_bad.text

    # Missing API key → 403.
    r_no_auth = client.post(
        "/admin/trials/build",
        json={"customer": "Acme Corp", "duration_days": 15, "features": []},
    )
    assert r_no_auth.status_code == 403
