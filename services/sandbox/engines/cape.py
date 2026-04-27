"""
CAPEv2 / Cuckoo sandbox engine.

CAPEv2 REST API (also compatible with Cuckoo 2.x):
  POST /apiv2/tasks/create/file/   → {"data": {"task_ids": [<id>]}}
  GET  /apiv2/tasks/view/<id>/     → {"data": {"status": "reported|running|pending|failed_analysis"}}
  GET  /apiv2/tasks/report/<id>/   → full JSON report
"""
import re
from typing import Optional

import aiohttp
import aiofiles

from .base import BaseSandboxEngine, SandboxReport


class CapeEngine(BaseSandboxEngine):
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")

    async def submit(self, file_path: str, file_name: str, sha256: str) -> str:
        async with aiofiles.open(file_path, "rb") as f:
            file_bytes = await f.read()

        async with aiohttp.ClientSession() as session:
            form = aiohttp.FormData()
            form.add_field("file", file_bytes, filename=file_name or sha256)
            form.add_field("options", "")
            form.add_field("package", "")
            form.add_field("timeout", "120")

            async with session.post(
                f"{self.base_url}/apiv2/tasks/create/file/",
                data=form,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                task_ids = data.get("data", {}).get("task_ids", [])
                if not task_ids:
                    raise RuntimeError(f"CAPEv2 returned no task_id: {data}")
                return str(task_ids[0])

    async def poll(self, task_id: str) -> Optional[SandboxReport]:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{self.base_url}/apiv2/tasks/view/{task_id}/",
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                resp.raise_for_status()
                view = await resp.json()

            status = view.get("data", {}).get("status", "")
            if status in ("pending", "running", "processing"):
                return None
            if status in ("failed_analysis", "failed_processing"):
                raise RuntimeError(f"CAPEv2 task {task_id} failed: {status}")
            if status != "reported":
                return None  # unknown transient state

            # Fetch full report
            async with session.get(
                f"{self.base_url}/apiv2/tasks/report/{task_id}/",
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                resp.raise_for_status()
                report = await resp.json()

        return self._parse_report(task_id, report)

    def _parse_report(self, task_id: str, report: dict) -> SandboxReport:
        info = report.get("info", {})
        score = int(info.get("score", 0) or 0)

        # Verdict
        if score >= 7:
            verdict = "malicious"
        elif score >= 4:
            verdict = "suspicious"
        else:
            verdict = "clean"

        # Malware family from signatures
        family = None
        for sig in report.get("signatures", []):
            if sig.get("families"):
                family = sig["families"][0]
                break

        # Extract IOCs from network section
        network = report.get("network", {})
        ips: list = []
        domains: list = []
        urls: list = []

        for host in network.get("hosts", []):
            ip = host if isinstance(host, str) else host.get("ip", "")
            if ip:
                ips.append(ip)

        for dns in network.get("dns", []):
            hostname = dns.get("hostname", "")
            if hostname and not re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
                domains.append(hostname)

        for req in network.get("http", []):
            url = req.get("uri", "") or req.get("url", "")
            if url and url.startswith("http"):
                urls.append(url)

        # Dropped file hashes
        hashes = []
        for dropped in report.get("dropped", []):
            sha256 = dropped.get("sha256")
            if sha256:
                hashes.append(sha256)

        return SandboxReport(
            task_id=task_id,
            verdict=verdict,
            malware_score=min(score * 10, 100),
            malware_family=family,
            extracted_iocs={"ips": ips, "domains": domains, "urls": urls, "hashes": hashes},
            report={"info": info, "score": score, "signatures": report.get("signatures", [])[:20]},
        )
