"""
PAN-OS XML API client.

Pulls the running config (XML) from a PAN-OS firewall via the management
API. Two auth modes:
  - api_key  (preferred — no creds in URL on every call)
  - user/password — automatically exchanged for an api_key on first use

PAN-OS endpoints:
  GET /api/?type=keygen&user=<u>&password=<p>     → <response status="success"><result><key>…</key></result></response>
  GET /api/?type=op&cmd=<show><config><running></running></config></show>&key=<k>
                                                 → <response><result><config>…</config></result></response>

We extract just the <config>…</config> subtree so the existing parser
(`engine/parsers/panos.py`) consumes it identically to a manually
uploaded `running-config.xml`.
"""
from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass
from typing import Any, Dict, Optional
from xml.etree import ElementTree as ET

import httpx

log = logging.getLogger(__name__)

_RUNNING_CMD = "<show><config><running></running></config></show>"


@dataclass
class FetchResult:
    config_bytes: bytes
    extension: str            # 'xml' for PA, 'conf' for F5
    content_type: str
    notes: Optional[str] = None


class PanosFetchError(Exception):
    pass


class PanosAuthError(PanosFetchError):
    pass


class PanosClient:
    def __init__(self, address: str, port: int = 443, *,
                 verify_tls: bool = False, timeout: float = 30.0):
        self.address = address
        self.port = port
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._base = f"https://{address}:{port}"

    async def _request(self, params: Dict[str, str]) -> ET.Element:
        async with httpx.AsyncClient(verify=self.verify_tls,
                                     timeout=self.timeout) as client:
            try:
                r = await client.get(f"{self._base}/api/", params=params)
            except httpx.RequestError as exc:
                raise PanosFetchError(f"connection failed: {exc}") from exc
        if r.status_code == 401 or r.status_code == 403:
            raise PanosAuthError(f"auth rejected (HTTP {r.status_code})")
        if r.status_code != 200:
            raise PanosFetchError(f"HTTP {r.status_code}: {r.text[:200]}")
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError as exc:
            raise PanosFetchError(f"non-XML response: {exc}") from exc
        if root.attrib.get("status") != "success":
            msg = (root.findtext("./msg/line") or root.findtext("./result")
                   or "unknown").strip()
            if "invalid" in msg.lower() or "not authorized" in msg.lower():
                raise PanosAuthError(f"auth rejected: {msg}")
            raise PanosFetchError(f"PAN-OS returned error: {msg}")
        return root

    async def keygen(self, user: str, password: str) -> str:
        root = await self._request({
            "type": "keygen", "user": user, "password": password,
        })
        key = root.findtext("./result/key")
        if not key:
            raise PanosAuthError("keygen returned no key")
        return key

    async def fetch_running_config(self, *, api_key: str) -> FetchResult:
        root = await self._request({"type": "op", "cmd": _RUNNING_CMD,
                                    "key": api_key})
        config_el = root.find("./result/config")
        if config_el is None:
            raise PanosFetchError("no <config> element in response")
        # Re-emit as a standalone XML doc so the file parser is happy.
        # Wrap the <config> subtree exactly like the on-disk running-config.
        body = ET.tostring(config_el, encoding="utf-8")
        return FetchResult(
            config_bytes=body,
            extension="xml",
            content_type="application/xml",
        )


async def fetch(address: str, port: int, credentials: Dict[str, Any],
                *, verify_tls: bool = False) -> FetchResult:
    """
    Top-level convenience: take credentials dict (api_key OR user+password),
    return a FetchResult. Raises PanosAuthError / PanosFetchError on failure.
    """
    client = PanosClient(address, port, verify_tls=verify_tls)
    api_key = credentials.get("api_key")
    if not api_key:
        user = credentials.get("user")
        password = credentials.get("password")
        if not user or not password:
            raise PanosAuthError("credentials must include api_key OR user+password")
        api_key = await client.keygen(user, password)
    return await client.fetch_running_config(api_key=api_key)
