"""
Internal graph-read endpoint. Returns a curated subgraph for the UI.
The api service proxies user requests here; we never expose raw Cypher.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.auth import require_api_key
from app.engine.subgraph import build_subgraph

log = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/graph", tags=["internal"])


class SubgraphOut(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    truncated: bool = False


@router.get("/subgraph", response_model=SubgraphOut,
            dependencies=[Depends(require_api_key)])
async def subgraph(
    asset_ip: Optional[str] = Query(None, description="Focus subgraph on paths to this asset IP"),
    max_hops: int = Query(6, ge=1, le=10),
    include_internet: bool = Query(True),
) -> SubgraphOut:
    nodes, edges, truncated = await build_subgraph(
        asset_ip=asset_ip,
        max_hops=max_hops,
        include_internet=include_internet,
    )
    return SubgraphOut(nodes=nodes, edges=edges, truncated=truncated)
