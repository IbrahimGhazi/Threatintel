"""
Analysis-result data classes — kept neo4j-free so they can be imported
by pure-Python consumers (scoring, findings, tests).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class PathCandidate:
    asset_ip: str
    hops: int
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    rules_cited: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class FanOutCandidate:
    kind: str
    props: Dict[str, Any]
    outdeg: int
    ingress_paths: int
