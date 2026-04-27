"""
Mock sandbox engine — for dev/testing when no real sandbox is available.

Behaviour:
  - Simulates a 10-second analysis delay.
  - Checks the TI platform's own indicator DB for the SHA256.
  - Returns "malicious" if already in DB with high confidence, else "clean".
  - Generates fake-but-realistic IOCs if malicious.
"""
import asyncio
import hashlib
from typing import Optional

import aiohttp

from .base import BaseSandboxEngine, SandboxReport

# Fake malicious C2 IPs returned in mock reports for realism
_MOCK_C2_IPS = ["185.220.101.34", "194.165.16.11", "45.142.212.100"]
_MOCK_DOMAINS = ["update.evil-cdn.net", "cdn.malware-drop.io"]


class MockEngine(BaseSandboxEngine):
    def __init__(self, api_url: str = "http://api:8000", api_key: str = ""):
        self.api_url = api_url.rstrip("/")
        self.headers = {"X-API-Key": api_key} if api_key else {}

    async def submit(self, file_path: str, file_name: str, sha256: str) -> str:
        # task_id is just the sha256 for the mock engine
        return sha256

    async def poll(self, task_id: str) -> Optional[SandboxReport]:
        sha256 = task_id
        # Simulate analysis time on first poll (caller polls every 15s anyway)
        await asyncio.sleep(5)

        verdict = "clean"
        malware_score = 5
        family = None
        ips, domains, urls = [], [], []

        # Check if this hash is already a known TI indicator
        try:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                async with session.get(
                    f"{self.api_url}/indicators/lookup/hash/{sha256}",
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        confidence = data.get("confidence", 0)
                        severity = data.get("severity", "info")
                        tags = data.get("tags", [])

                        if confidence >= 70 or severity in ("critical", "high"):
                            verdict = "malicious"
                            malware_score = confidence
                            family = next((t for t in tags if t not in ("hash", "sha256", "md5")), "Unknown")
                            ips = _MOCK_C2_IPS[:2]
                            domains = _MOCK_DOMAINS[:1]
                            urls = [f"http://{_MOCK_DOMAINS[0]}/payload/{sha256[:8]}"]
                        elif confidence >= 40 or severity == "medium":
                            verdict = "suspicious"
                            malware_score = confidence
        except Exception:
            pass

        return SandboxReport(
            task_id=sha256,
            verdict=verdict,
            malware_score=malware_score,
            malware_family=family if verdict == "malicious" else None,
            extracted_iocs={"ips": ips, "domains": domains, "urls": urls, "hashes": []},
            report={"engine": "mock", "note": "Simulated analysis for development environment"},
        )
