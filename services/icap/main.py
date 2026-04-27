"""
ICAP service entry point.
Starts the ICAP server and Prometheus metrics server.
"""
import asyncio
import logging
import os
import sys
from threading import Thread

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "service": "icap", "message": "%(message)s"}',
    stream=sys.stdout,
)
logger = logging.getLogger("icap")


def start_metrics_server():
    """Run Prometheus metrics HTTP server on port 9003."""
    from prometheus_client import start_http_server
    start_http_server(9003)
    logger.info("Prometheus metrics available on :9003")


if __name__ == "__main__":
    # Start metrics in background thread
    Thread(target=start_metrics_server, daemon=True).start()

    from server import run_icap_server
    asyncio.run(run_icap_server())
