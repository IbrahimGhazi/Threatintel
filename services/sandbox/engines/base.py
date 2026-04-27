"""
Abstract base class for sandbox engines.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SandboxReport:
    task_id: str
    verdict: str                    # malicious | suspicious | clean | error
    malware_score: int              # 0-100
    malware_family: Optional[str]
    extracted_iocs: Dict[str, List[str]] = field(default_factory=lambda: {
        "ips": [], "domains": [], "urls": [], "hashes": []
    })
    report: Dict[str, Any] = field(default_factory=dict)


class BaseSandboxEngine(ABC):
    """All engines must implement submit() and poll()."""

    @abstractmethod
    async def submit(self, file_path: str, file_name: str, sha256: str) -> str:
        """Submit file for analysis. Returns an engine-specific task_id."""

    @abstractmethod
    async def poll(self, task_id: str) -> Optional[SandboxReport]:
        """
        Check analysis status.
        Returns SandboxReport when complete, None if still pending.
        Raises RuntimeError on unrecoverable error.
        """
