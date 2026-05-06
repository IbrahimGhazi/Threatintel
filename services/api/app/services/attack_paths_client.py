"""
HTTP client for the attack-paths worker service.

The api router stays thin: Postgres-backed reads (uploads/findings/runs)
are direct, but anything that touches Neo4j or kicks off a run goes here.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0)


class AttackPathsClient:
    def __init__(self, base_url: Optional[str] = None,
                 api_key: Optional[str] = None) -> None:
        self.base_url = (base_url or os.environ.get("ATTACK_PATHS_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("API_KEY", "")

    @property
    def enabled(self) -> bool:
        return bool(self.base_url)

    def _headers(self) -> Dict[str, str]:
        return {"X-API-Key": self.api_key} if self.api_key else {}

    async def trigger_run(self, *, upload_ids: List[str],
                          triggered_by: Optional[str] = None) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            r = await client.post(
                f"{self.base_url}/internal/runs",
                json={"upload_ids": upload_ids, "triggered_by": triggered_by},
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()

    async def fetch_subgraph(self, *, asset_ip: Optional[str] = None,
                             max_hops: int = 6,
                             include_internet: bool = True) -> Dict[str, Any]:
        params: Dict[str, Any] = {"max_hops": max_hops,
                                  "include_internet": include_internet}
        if asset_ip:
            params["asset_ip"] = asset_ip
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            r = await client.get(
                f"{self.base_url}/internal/graph/subgraph",
                params=params, headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()

    # ── Device registry passthroughs ──────────────────────────────────────────

    async def list_devices(self) -> List[Dict[str, Any]]:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            r = await client.get(f"{self.base_url}/internal/devices",
                                 headers=self._headers())
            r.raise_for_status()
            return r.json()

    async def get_device(self, device_id: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            r = await client.get(f"{self.base_url}/internal/devices/{device_id}",
                                 headers=self._headers())
            r.raise_for_status()
            return r.json()

    async def create_device(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            r = await client.post(f"{self.base_url}/internal/devices",
                                  json=payload, headers=self._headers())
            if r.status_code >= 400:
                # Re-raise with the upstream detail so the user sees vendor errors.
                raise httpx.HTTPStatusError(
                    f"{r.status_code}: {r.text}", request=r.request, response=r,
                )
            return r.json()

    async def patch_device(self, device_id: str,
                           payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            r = await client.patch(f"{self.base_url}/internal/devices/{device_id}",
                                   json=payload, headers=self._headers())
            r.raise_for_status()
            return r.json()

    async def delete_device(self, device_id: str) -> None:
        async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
            r = await client.delete(f"{self.base_url}/internal/devices/{device_id}",
                                    headers=self._headers())
            r.raise_for_status()

    async def fetch_device_now(self, device_id: str) -> Dict[str, Any]:
        # Allow extra time for a slow first-fetch over the WAN.
        timeout = httpx.Timeout(connect=5.0, read=120.0, write=10.0, pool=5.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(
                f"{self.base_url}/internal/devices/{device_id}/fetch",
                headers=self._headers(),
            )
            r.raise_for_status()
            return r.json()
