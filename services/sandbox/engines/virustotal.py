"""
VirusTotal v3 sandbox engine.

Free tier:  upload + AV scan results (verdict from consensus).
Premium:    also calls /behaviour_summary for network IOCs.

Flow:
  POST /api/v3/files              → analysis_id
  GET  /api/v3/analyses/{id}      → poll until status == "completed"
  GET  /api/v3/files/{sha256}     → full report (AV results, crowdsourced IOCs)
  GET  /api/v3/files/{sha256}/behaviour_summary  → network IOCs (premium only, fails silently)
"""
import asyncio
from typing import Optional

import aiohttp
import aiofiles

from .base import BaseSandboxEngine, SandboxReport

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalEngine(BaseSandboxEngine):
    def __init__(self, api_key: str):
        self.headers = {"x-apikey": api_key}

    async def submit(self, file_path: str, file_name: str, sha256: str) -> str:
        # First check if VT already has a report for this hash
        async with aiohttp.ClientSession(headers=self.headers) as session:
            async with session.get(
                f"{VT_BASE}/files/{sha256}",
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    # Already analysed – return sha256 as the "task_id" (skip resubmission)
                    return f"existing:{sha256}"

            # Upload file
            async with aiofiles.open(file_path, "rb") as f:
                file_bytes = await f.read()

            form = aiohttp.FormData()
            form.add_field("file", file_bytes, filename=file_name or sha256)

            async with session.post(
                f"{VT_BASE}/files",
                data=form,
                timeout=aiohttp.ClientTimeout(total=120),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()
                return data["data"]["id"]  # analysis_id

    async def poll(self, task_id: str) -> Optional[SandboxReport]:
        async with aiohttp.ClientSession(headers=self.headers) as session:
            if task_id.startswith("existing:"):
                sha256 = task_id.split(":", 1)[1]
                return await self._fetch_report(session, sha256)

            # Poll analysis status
            async with session.get(
                f"{VT_BASE}/analyses/{task_id}",
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                resp.raise_for_status()
                data = await resp.json()

            status = data["data"]["attributes"].get("status")
            if status != "completed":
                return None  # still queued / in-progress

            # Get SHA256 from the completed analysis meta
            meta_sha256 = (
                data.get("meta", {})
                    .get("file_info", {})
                    .get("sha256", "")
            )
            if not meta_sha256:
                raise RuntimeError("VirusTotal analysis completed but SHA256 missing from meta")

            return await self._fetch_report(session, meta_sha256)

    async def _fetch_report(self, session: aiohttp.ClientSession, sha256: str) -> SandboxReport:
        async with session.get(
            f"{VT_BASE}/files/{sha256}",
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()

        attrs = data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        total = sum(stats.values()) or 1
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        score = int(((malicious + suspicious * 0.5) / total) * 100)

        if malicious >= 3:
            verdict = "malicious"
        elif malicious >= 1 or suspicious >= 3:
            verdict = "suspicious"
        else:
            verdict = "clean"

        # Malware family from popular threat label
        family = None
        popular_label = attrs.get("popular_threat_classification", {})
        suggested = popular_label.get("suggested_threat_label", "")
        if "/" in suggested:
            family = suggested.split("/")[-1]
        elif suggested:
            family = suggested

        # Try behaviour_summary (premium) — fails silently on 403
        ips, domains, urls = [], [], []
        try:
            async with session.get(
                f"{VT_BASE}/files/{sha256}/behaviour_summary",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    bdata = await resp.json()
                    battrs = bdata.get("data", {}).get("attributes", {})
                    ips = list(set(battrs.get("ip_traffic", []) or []))
                    domains = list(set(battrs.get("dns_lookups", []) or []))
                    urls = list(set(battrs.get("http_conversations", []) or []))
                    if isinstance(ips[0], dict) if ips else False:
                        ips = [x.get("destination_ip", "") for x in ips if x.get("destination_ip")]
        except Exception:
            pass

        # Crowdsourced IOCs from sandbox reports (available on free tier)
        for sandbox_report in attrs.get("sandbox_verdicts", {}).values():
            for ip in sandbox_report.get("network_infrastructure", {}).get("ip_addresses", []):
                if ip not in ips:
                    ips.append(ip)

        return SandboxReport(
            task_id=sha256,
            verdict=verdict,
            malware_score=score,
            malware_family=family,
            extracted_iocs={"ips": ips, "domains": domains, "urls": urls, "hashes": []},
            report={
                "stats": stats,
                "threat_label": suggested,
                "sandbox_verdicts": attrs.get("sandbox_verdicts", {}),
                "tags": attrs.get("tags", []),
            },
        )
