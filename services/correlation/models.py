from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ParsedEvent:
    timestamp: str
    stage: str
    action: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    hostname: Optional[str]
    program: Optional[str]
    status: Optional[str]
    log_id: str
    summary: str


@dataclass
class MitreMapping:
    tactic: str
    technique_id: str
    technique: str


@dataclass
class Incident:
    attack_type: str
    severity: str
    title: str
    description: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    affected_host: Optional[str]
    affected_hosts: List[str]
    related_log_ids: List[str]
    event_count: int
    time_window: Dict[str, Any]
    mitre_attack: List[Dict[str, str]]
    event_chain: List[Dict[str, Any]]
    stages: List[str]
    stage_progression: List[Dict[str, Any]]
    recommended_action: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_context(self) -> Dict[str, Any]:
        context = {
            "attack_type": self.attack_type,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "affected_host": self.affected_host,
            "affected_hosts": self.affected_hosts,
            "related_logs": self.related_log_ids,
            "event_count": self.event_count,
            "time_window": self.time_window,
            "mitre_attack": self.mitre_attack,
            "event_chain": self.event_chain,
            "stages": self.stages,
            "stage_progression": self.stage_progression,
            "recommended_action": self.recommended_action,
        }
        context.update(self.metadata)
        return context