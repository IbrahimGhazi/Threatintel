"""
F5 BIG-IP iControl REST client.

Pulls the full TMOS running config by executing `tmsh -q list /` via the
`/mgmt/tm/util/bash` endpoint. Output is the same text format consumed by
the existing parser (`engine/parsers/f5.py`).

We don't use UCS download here because:
  - UCS is binary + needs unpacking
  - Includes a lot of state we don't care about (certs, license)
  - tmsh list / is text, idempotent, fast
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from app.devices.panos_client import FetchResult  # reuse dataclass

log = logging.getLogger(__name__)


class F5FetchError(Exception):
    pass


class F5AuthError(F5FetchError):
    pass


class F5Client:
    def __init__(self, address: str, port: int = 443, *,
                 verify_tls: bool = False, timeout: float = 60.0):
        self.address = address
        self.port = port
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._base = f"https://{address}:{port}"

    async def _post(self, path: str, body: Dict[str, Any], auth: tuple) -> Dict[str, Any]:
        async with httpx.AsyncClient(verify=self.verify_tls,
                                     timeout=self.timeout, auth=auth) as client:
            try:
                r = await client.post(f"{self._base}{path}", json=body)
            except httpx.RequestError as exc:
                raise F5FetchError(f"connection failed: {exc}") from exc
        if r.status_code == 401:
            raise F5AuthError("auth rejected (HTTP 401)")
        if r.status_code == 403:
            raise F5AuthError("auth rejected (HTTP 403 — user lacks bash access?)")
        if r.status_code >= 400:
            raise F5FetchError(f"HTTP {r.status_code}: {r.text[:300]}")
        try:
            return r.json()
        except ValueError as exc:
            raise F5FetchError(f"non-JSON response: {exc}") from exc

    async def fetch_running_config(self, *, user: str, password: str) -> FetchResult:
        body = {
            "command": "run",
            # tmsh -q (quiet) list / = full LTM/GTM/etc. running config in text.
            # The 2>&1 redirect catches transient warnings into the same blob,
            # which is harmless for our parser (extra lines are ignored).
            "utilCmdArgs": "-c 'tmsh -q list / 2>&1'",
        }
        out = await self._post("/mgmt/tm/util/bash", body, auth=(user, password))
        text = out.get("commandResult")
        if not text:
            raise F5FetchError("empty commandResult — bash may be disabled "
                               "or the user lacks shell access")
        return FetchResult(
            config_bytes=text.encode("utf-8"),
            extension="conf",
            content_type="text/plain",
        )


async def fetch(address: str, port: int, credentials: Dict[str, Any],
                *, verify_tls: bool = False) -> FetchResult:
    user = credentials.get("user")
    password = credentials.get("password")
    if not user or not password:
        raise F5AuthError("F5 credentials must include user and password")
    client = F5Client(address, port, verify_tls=verify_tls)
    return await client.fetch_running_config(user=user, password=password)
