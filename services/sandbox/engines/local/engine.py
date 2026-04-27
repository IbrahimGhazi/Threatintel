"""
Local sandbox engine — orchestrates static + dynamic analysis with real-time
progress tracking via Redis/SSE.

Flow:
  submit(file_path, file_name, sha256) → background task, returns sha256
  poll(sha256)                          → SandboxReport when done, else None
"""
import asyncio
import logging
import os
from typing import Dict, Optional

from engines.base import BaseSandboxEngine, SandboxReport
from .static   import StaticAnalyzer
from .dynamic  import DynamicAnalyzer
from .progress import ProgressEmitter

log = logging.getLogger(__name__)

DYNAMIC_ENABLED = os.getenv("LOCAL_SANDBOX_DYNAMIC", "true").lower() == "true"

EXEC_TYPES = (
    "PE/Windows Executable",
    "ELF/Linux Executable",
    "Shell/Script",
    "PHP Script",
    "Java Class",
    "Android DEX",
    "Python Script",
    "PowerShell Script",
    "Batch Script",
)


class LocalSandboxEngine(BaseSandboxEngine):
    name = "local"

    def __init__(self):
        self._static   = StaticAnalyzer()
        self._dynamic  = DynamicAnalyzer()
        self._tasks:   Dict[str, asyncio.Task]   = {}
        self._results: Dict[str, SandboxReport]  = {}

    async def submit(self, file_path: str, file_name: str, sha256: str) -> str:
        log.info("[local] Submitting %s (%s)", file_name, sha256[:12])
        # Pre-seed the progress key so the SSE endpoint can show "queued" immediately
        loop = asyncio.get_event_loop()
        progress = ProgressEmitter(sha256)
        await loop.run_in_executor(None, progress.mark_done, "file_received")
        await loop.run_in_executor(None, progress.mark_running, "queued")

        task = asyncio.create_task(
            self._analyse(file_path, file_name, sha256, progress),
            name=f"local-sandbox-{sha256[:12]}",
        )
        self._tasks[sha256] = task
        return sha256

    async def poll(self, task_id: str) -> Optional[SandboxReport]:
        task = self._tasks.get(task_id)
        if task is None:
            return self._results.pop(task_id, None)
        if not task.done():
            return None
        del self._tasks[task_id]
        exc = task.exception()
        if exc:
            raise RuntimeError(f"Local sandbox failed: {exc}") from exc
        return self._results.pop(task_id, None)

    # ── Pipeline ───────────────────────────────────────────────────────────────

    async def _analyse(
        self, file_path: str, file_name: str, sha256: str, progress: ProgressEmitter
    ):
        loop = asyncio.get_event_loop()

        try:
            # ── Queue ────────────────────────────────────────────────────
            await asyncio.sleep(0.2)  # brief pause so "queued" is visible
            await loop.run_in_executor(None, progress.mark_done, "queued")

            # ── Static Analysis ───────────────────────────────────────────
            await loop.run_in_executor(None, progress.mark_running, "static_analysis")
            try:
                static = await loop.run_in_executor(
                    None, self._static.analyze, file_path
                )
            except Exception as exc:
                log.error("[local] Static analysis failed: %s", exc, exc_info=True)
                static = {
                    "error": str(exc), "suspicious_score": 0,
                    "suspicious_reasons": [], "iocs": {}, "packers": [],
                    "file_type": "unknown", "entropy": 0.0,
                }
            await loop.run_in_executor(None, progress.mark_done, "static_analysis")

            # ── Dynamic Analysis ──────────────────────────────────────────
            file_type = static.get("file_type", "")
            dynamic: Optional[Dict] = None

            if DYNAMIC_ENABLED and any(file_type.startswith(t) for t in EXEC_TYPES):
                await loop.run_in_executor(None, progress.mark_running, "sandbox_prep")
                try:
                    # Heartbeat task: re-pushes current stage state every 8 s so the
                    # SSE stream keeps flowing during long blocking executor calls.
                    async def _heartbeat():
                        try:
                            while True:
                                await asyncio.sleep(8)
                                await loop.run_in_executor(None, progress.touch)
                        except asyncio.CancelledError:
                            pass

                    _hb = asyncio.create_task(_heartbeat())
                    try:
                        dynamic = await self._dynamic.run(
                            file_path, file_name, sha256, progress=progress
                        )
                    finally:
                        _hb.cancel()
                        await asyncio.gather(_hb, return_exceptions=True)
                    # run() returns an error dict instead of raising when Docker is
                    # unavailable or the analysis image fails to build.  Detect this
                    # and skip the dynamic stages so the pipeline can advance.
                    if dynamic.get("error") and not dynamic.get("executed"):
                        log.warning("[local] Dynamic analysis unavailable: %s", dynamic["error"])
                        await loop.run_in_executor(None, progress.mark_skipped, "sandbox_prep")
                        await loop.run_in_executor(None, progress.mark_skipped, "behavioral_exec")
                        await loop.run_in_executor(None, progress.mark_skipped, "time_manipulation")
                except Exception as exc:
                    log.error("[local] Dynamic analysis failed: %s", exc, exc_info=True)
                    dynamic = {"error": str(exc), "behavioral": []}
                    await loop.run_in_executor(None, progress.mark_skipped, "sandbox_prep")
                    await loop.run_in_executor(None, progress.mark_skipped, "behavioral_exec")
                    await loop.run_in_executor(None, progress.mark_skipped, "time_manipulation")
            else:
                await loop.run_in_executor(None, progress.mark_skipped, "sandbox_prep")
                await loop.run_in_executor(None, progress.mark_skipped, "behavioral_exec")
                await loop.run_in_executor(None, progress.mark_skipped, "time_manipulation")

            # ── IOC Extraction ────────────────────────────────────────────
            await loop.run_in_executor(None, progress.mark_running, "ioc_extraction")
            iocs = _merge_iocs(static, dynamic)
            await loop.run_in_executor(None, progress.mark_done, "ioc_extraction")

            # ── Report Generation ─────────────────────────────────────────
            await loop.run_in_executor(None, progress.mark_running, "report_generation")
            verdict, score, family = _verdict(static, dynamic)
            report = SandboxReport(
                task_id        = sha256,
                verdict        = verdict,
                malware_score  = score,
                malware_family = family,
                extracted_iocs = iocs,
                report         = {
                    "engine":              "local",
                    "static":              static,
                    "dynamic":             dynamic,
                    "behavioral_summary":  _behavioral_summary(dynamic),
                    "evasion_attempts":    _evasion_attempts(static, dynamic),
                },
            )
            self._results[sha256] = report
            await loop.run_in_executor(None, progress.mark_done, "report_generation")
            await loop.run_in_executor(None, progress.mark_complete)

            log.info("[local] Complete: %s → %s (score=%d)", sha256[:12], verdict, score)

        except Exception as exc:
            log.error("[local] Pipeline error: %s", exc, exc_info=True)
            await loop.run_in_executor(None, progress.mark_failed, str(exc))
            raise


# ── Helpers ────────────────────────────────────────────────────────────────────

def _merge_iocs(static: Dict, dynamic: Optional[Dict]) -> Dict:
    ips     = set(static.get("iocs", {}).get("ips", []))
    domains = set(static.get("iocs", {}).get("domains", []))
    urls    = set(static.get("iocs", {}).get("urls", []))
    hashes: set = set()

    if dynamic:
        strace = dynamic.get("strace", {})
        pcap   = dynamic.get("pcap", {})
        ips     |= set(strace.get("ips", [])) | set(pcap.get("ips", []))
        domains |= set(strace.get("domains", [])) | set(pcap.get("domains", []))
        urls    |= set(pcap.get("urls", []))
        hashes  |= set(dynamic.get("dropped_hashes", []))

    _local = ("127.", "10.", "172.16.", "172.17.", "192.168.", "0.")
    ips = {ip for ip in ips if not any(ip.startswith(p) for p in _local)}

    return {"ips": list(ips), "domains": list(domains), "urls": list(urls), "hashes": list(hashes)}


def _verdict(static: Dict, dynamic: Optional[Dict]):
    score  = static.get("suspicious_score", 0)
    family = None
    SEV    = {"critical": 30, "high": 20, "medium": 10, "low": 5}

    if dynamic:
        for ind in dynamic.get("behavioral", []):
            score = min(100, score + SEV.get(ind.get("severity", "low"), 5))
        btypes = {i["type"] for i in dynamic.get("behavioral", [])}
        if "ransomware"    in btypes: family = "Ransomware"
        elif "c2_beacon"   in btypes: family = "Trojan/C2"
        elif "fileless_exec" in btypes or "memory_exec" in btypes: family = "Fileless Malware"

    verdict = "malicious" if score >= 70 else "suspicious" if score >= 35 else "clean"
    return verdict, score, family


def _behavioral_summary(dynamic: Optional[Dict]) -> list:
    return dynamic.get("behavioral", []) if dynamic else []


def _evasion_attempts(static: Dict, dynamic: Optional[Dict]) -> list:
    evasions = []
    if static.get("packers"):
        evasions.append(f"Packed/obfuscated: {', '.join(static['packers'])}")
    pe = static.get("pe") or {}
    if isinstance(pe, dict) and pe.get("tls_callbacks"):
        evasions.append("TLS callbacks (code before entry point)")
    if dynamic:
        for ind in dynamic.get("behavioral", []):
            if ind["type"] in ("anti_debug", "anti_vm", "fileless_exec"):
                evasions.append(ind["description"])
    return evasions
