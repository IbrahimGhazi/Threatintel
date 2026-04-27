"""
Reverse DNS enrichment – resolve IP to hostname.
"""
import asyncio
import socket
from typing import Any, Dict

from modules.base import BaseEnricher


class ReverseDNSEnricher(BaseEnricher):
    name = "rdns"
    supported_types = ["ip"]
    cache_ttl = 3600  # 1 hour

    async def _enrich(self, indicator_type: str, value: str) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        try:
            hostname = await loop.run_in_executor(
                None, lambda: socket.gethostbyaddr(value)[0]
            )
            return {"hostname": hostname}
        except (socket.herror, socket.gaierror):
            return {"hostname": None}
