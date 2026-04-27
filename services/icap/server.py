"""
ICAP Server – asyncio-based, handles REQMOD and RESPMOD.

Architecture:
  - asyncio TCP server (one coroutine per connection)
  - ICAPConnectionHandler reads requests, routes to REQMOD/RESPMOD handlers
  - Handlers check URLs/IPs against TI database via Redis cache + API fallback
  - Decision: allow (204 No Modification) or block (200 with 403 body)
"""
import asyncio
import hashlib
import logging
import os
import re
import urllib.parse
from typing import Optional, Tuple

import httpx
import redis.asyncio as aioredis
import tldextract

from protocol import (
    ICAPRequest, ICAPResponseBuilder,
    ICAP_NOT_FOUND, ICAP_NOT_IMPLEMENTED, ICAP_BAD_REQUEST, ICAP_SERVER_ERR,
    parse_icap_request,
)

logger = logging.getLogger(__name__)

API_URL = os.getenv("API_URL", "http://api:8000")
API_KEY = os.getenv("API_KEY", "")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/3")
MAX_CONNECTIONS = int(os.getenv("ICAP_MAX_CONNECTIONS", "100"))
ICAP_HOST = os.getenv("ICAP_HOST", "0.0.0.0")
ICAP_PORT = int(os.getenv("ICAP_PORT", "1344"))

VERDICT_TTL = 300  # Cache lookup verdicts for 5 minutes
BLOCK_TTL = 3600   # Cache block verdicts for 1 hour

response_builder = ICAPResponseBuilder()

# Semaphore to limit concurrent connections
connection_semaphore: asyncio.Semaphore = None


# ── Indicator lookup ──────────────────────────────────────────

async def check_indicator(
    redis: aioredis.Redis,
    api_client: httpx.AsyncClient,
    itype: str,
    value: str,
) -> Tuple[bool, str]:
    """
    Check an indicator against the TI database.

    Returns (is_malicious, reason).
    Uses Redis as a fast L1 cache; falls back to API on miss.
    """
    cache_key = f"icap:verdict:{itype}:{value}"

    try:
        cached = await redis.get(cache_key)
        if cached is not None:
            is_block = cached == b"block"
            return is_block, "cached verdict"
    except Exception:
        pass  # Continue without cache

    # API lookup
    try:
        if itype == "ip":
            endpoint = f"/indicators/lookup/ip/{value}"
        elif itype == "domain":
            endpoint = f"/indicators/lookup/domain/{value}"
        elif itype == "url":
            endpoint = f"/indicators/lookup/url?url={urllib.parse.quote(value)}"
        elif itype in ("sha256", "md5", "sha1"):
            endpoint = f"/indicators/lookup/hash/{value}"
        else:
            return False, ""

        resp = await api_client.get(
            f"{API_URL}{endpoint}",
            headers={"X-API-Key": API_KEY},
            timeout=2.0,
        )

        if resp.status_code == 404:
            # Not in TI database – allow
            await redis.setex(cache_key, VERDICT_TTL, b"allow")
            return False, ""

        if resp.status_code == 200:
            data = resp.json()
            confidence = data.get("confidence", 0)
            severity = data.get("severity", "info")

            # Block if high confidence malicious indicator
            is_malicious = confidence >= 70 and severity in ("high", "critical")
            verdict = b"block" if is_malicious else b"allow"
            ttl = BLOCK_TTL if is_malicious else VERDICT_TTL

            await redis.setex(cache_key, ttl, verdict)
            if is_malicious:
                reason = f"TI match: {itype}={value} confidence={confidence} severity={severity}"
                return True, reason
            return False, ""

    except Exception as exc:
        logger.warning("API lookup failed for %s %s: %s", itype, value[:60], exc)

    return False, ""


def extract_indicators_from_request(req: ICAPRequest) -> list:
    """Extract checkable indicators from an ICAP request."""
    indicators = []

    # Get URL from HTTP Host + request URI
    host = req.req_headers.get("host", "")
    request_uri = ""
    if host:
        indicators.append(("domain", host.split(":")[0]))

    # Try to extract URL from first req header line (GET /path HTTP/1.1)
    # We do this from encapsulated body parsing
    # For REQMOD, the request URL is in the ICAP URI or req headers

    return indicators


def extract_url_from_icap_uri(icap_uri: str) -> Optional[str]:
    """
    Some proxy implementations embed the full request URL in the ICAP URI.
    Example: icap://icap-server:1344/reqmod?http://target.com/path
    """
    if "?" in icap_uri:
        return icap_uri.split("?", 1)[1]
    return None


class ICAPConnectionHandler:
    """Handles a single ICAP client connection."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        redis: aioredis.Redis,
        api_client: httpx.AsyncClient,
    ):
        self.reader = reader
        self.writer = writer
        self.redis = redis
        self.api = api_client
        self.peer = writer.get_extra_info("peername", ("unknown", 0))

    async def handle(self):
        logger.debug("New ICAP connection from %s:%d", *self.peer)
        try:
            await self._handle_loop()
        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as exc:
            logger.error("ICAP handler error from %s: %s", self.peer[0], exc, exc_info=True)
        finally:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass

    async def _handle_loop(self):
        """Handle multiple ICAP requests on a persistent connection."""
        buffer = b""
        while True:
            try:
                chunk = await asyncio.wait_for(self.reader.read(65536), timeout=30)
                if not chunk:
                    break
                buffer += chunk

                req, consumed = parse_icap_request(buffer)
                if req is None:
                    if len(buffer) > 1 * 1024 * 1024:  # 1MB max buffer
                        self._send(response_builder.error_response(ICAP_BAD_REQUEST))
                        break
                    continue  # Need more data

                buffer = buffer[consumed:]
                await self._dispatch(req)

            except asyncio.TimeoutError:
                break

    async def _dispatch(self, req: ICAPRequest):
        method = req.method.upper()
        service = req.service

        if method == "OPTIONS":
            await self._handle_options(req)
        elif method == "REQMOD" and service == "reqmod":
            await self._handle_reqmod(req)
        elif method == "RESPMOD" and service == "respmod":
            await self._handle_respmod(req)
        else:
            self._send(response_builder.error_response(ICAP_NOT_FOUND))

    async def _handle_options(self, req: ICAPRequest):
        service = req.service
        if service == "reqmod":
            resp = response_builder.options_response("reqmod", ["REQMOD"])
        elif service == "respmod":
            resp = response_builder.options_response("respmod", ["RESPMOD"])
        else:
            resp = response_builder.options_response("ti-platform", ["REQMOD", "RESPMOD"])
        self._send(resp)

    async def _handle_reqmod(self, req: ICAPRequest):
        """
        Inspect outbound HTTP requests.
        Extract destination URL/domain/IP and check against TI database.
        """
        try:
            # Extract destination from request headers
            host = req.req_headers.get("host", "").split(":")[0]
            indicators_to_check = []

            if host:
                indicators_to_check.append(("domain", host))

            # Also check if it looks like an IP
            import ipaddress
            try:
                ipaddress.ip_address(host)
                indicators_to_check.append(("ip", host))
            except ValueError:
                pass

            for itype, value in indicators_to_check:
                is_malicious, reason = await check_indicator(self.redis, self.api, itype, value)
                if is_malicious:
                    logger.info("REQMOD BLOCK: %s=%s reason=%s peer=%s", itype, value, reason, self.peer[0])
                    self._send(response_builder.block_response(reason))
                    return

            # Allow passthrough
            self._send(response_builder.no_modification())

        except Exception as exc:
            logger.error("REQMOD error: %s", exc)
            self._send(response_builder.no_modification())  # Fail-open

    async def _handle_respmod(self, req: ICAPRequest):
        """
        Inspect inbound HTTP responses.
        Check URLs and compute file hashes for downloads.
        """
        try:
            host = req.req_headers.get("host", "").split(":")[0]

            if host:
                is_malicious, reason = await check_indicator(self.redis, self.api, "domain", host)
                if is_malicious:
                    logger.info("RESPMOD BLOCK domain: %s peer=%s", host, self.peer[0])
                    self._send(response_builder.block_response(reason))
                    return

            # Check file hash if body is present
            if req.encapsulated_body and len(req.encapsulated_body) > 0:
                content_type = req.res_headers.get("content-type", "").lower()
                # Only hash potentially executable content
                if any(ct in content_type for ct in
                       ("octet-stream", "executable", "zip", "x-msdownload", "x-dosexec")):
                    sha256 = hashlib.sha256(req.encapsulated_body).hexdigest()
                    is_malicious, reason = await check_indicator(self.redis, self.api, "sha256", sha256)
                    if is_malicious:
                        logger.info("RESPMOD BLOCK hash: %s peer=%s", sha256, self.peer[0])
                        self._send(response_builder.block_response(reason))
                        return

            self._send(response_builder.no_modification())

        except Exception as exc:
            logger.error("RESPMOD error: %s", exc)
            self._send(response_builder.no_modification())  # Fail-open

    def _send(self, data: bytes):
        self.writer.write(data)


async def run_icap_server():
    """Start the ICAP TCP server."""
    redis = aioredis.from_url(REDIS_URL, decode_responses=False)
    api_client = httpx.AsyncClient(
        timeout=3.0,
        limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
    )

    global connection_semaphore
    connection_semaphore = asyncio.Semaphore(MAX_CONNECTIONS)

    async def handle_connection(reader, writer):
        async with connection_semaphore:
            handler = ICAPConnectionHandler(reader, writer, redis, api_client)
            await handler.handle()

    server = await asyncio.start_server(
        handle_connection,
        host=ICAP_HOST,
        port=ICAP_PORT,
        reuse_address=True,
    )

    logger.info("ICAP server listening on %s:%d", ICAP_HOST, ICAP_PORT)
    logger.info("Services: icap://<host>:%d/reqmod | icap://<host>:%d/respmod", ICAP_PORT, ICAP_PORT)

    async with server:
        await server.serve_forever()
