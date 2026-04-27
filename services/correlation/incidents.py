from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import Incident
from parser import ParsedLog


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def summarize_event(log: ParsedLog, stage: str) -> Dict[str, Any]:
    summary_bits = []
    if log.action:
        summary_bits.append(log.action)
    if log.status:
        summary_bits.append(log.status)
    if log.process_name:
        summary_bits.append(log.process_name)
    if log.dst_ip:
        summary_bits.append(f"to {log.dst_ip}")
    if log.dst_port:
        summary_bits.append(f"port {log.dst_port}")

    return {
        "timestamp": _iso(log.timestamp),
        "stage": stage,
        "action": log.action,
        "source_ip": log.src_ip,
        "destination_ip": log.dst_ip,
        "destination_port": log.dst_port,
        "hostname": log.hostname,
        "program": log.process_name,
        "status": log.status,
        "log_id": log.log_id,
        "summary": " ".join(summary_bits) or (log.raw[:160] if log.raw else stage),
    }


def build_incident(
    *,
    attack_type: str,
    severity: str,
    title: str,
    description: str,
    recommended_action: str,
    logs: List[ParsedLog],
    stage_map: Optional[Dict[str, List[ParsedLog]]] = None,
    mitre_attack: Optional[List[Dict[str, str]]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    affected_host: Optional[str] = None,
) -> Incident:
    ordered_logs = sorted(logs, key=lambda item: item.timestamp)
    stage_map = stage_map or {}
    event_chain: List[Dict[str, Any]] = []
    stage_progression: List[Dict[str, Any]] = []
    stage_names: List[str] = []

    if stage_map:
        for stage, stage_logs in stage_map.items():
            if not stage_logs:
                continue
            stage_names.append(stage)
            sorted_stage_logs = sorted(stage_logs, key=lambda item: item.timestamp)
            for entry in sorted_stage_logs:
                event_chain.append(summarize_event(entry, stage))
            stage_progression.append(
                {
                    "stage": stage,
                    "count": len(sorted_stage_logs),
                    "first_seen": _iso(sorted_stage_logs[0].timestamp),
                    "last_seen": _iso(sorted_stage_logs[-1].timestamp),
                    "status": "completed",
                }
            )
    else:
        inferred_stage = attack_type.replace("_", " ")
        stage_names = [inferred_stage]
        for entry in ordered_logs:
            event_chain.append(summarize_event(entry, inferred_stage))
        if ordered_logs:
            stage_progression.append(
                {
                    "stage": inferred_stage,
                    "count": len(ordered_logs),
                    "first_seen": _iso(ordered_logs[0].timestamp),
                    "last_seen": _iso(ordered_logs[-1].timestamp),
                    "status": "completed",
                }
            )

    event_chain.sort(key=lambda item: item["timestamp"])

    hosts = sorted(
        {
            value
            for value in [
                affected_host,
                *(log.hostname for log in ordered_logs if log.hostname),
                *(log.dst_ip for log in ordered_logs if log.dst_ip),
                *(log.src_ip for log in ordered_logs if log.src_ip),
            ]
            if value
        }
    )

    if ordered_logs:
        window = {
            "start": _iso(ordered_logs[0].timestamp),
            "end": _iso(ordered_logs[-1].timestamp),
            "duration_seconds": max(0, int(ordered_logs[-1].timestamp - ordered_logs[0].timestamp)),
        }
    else:
        now = datetime.now(timezone.utc).isoformat()
        window = {"start": now, "end": now, "duration_seconds": 0}

    return Incident(
        attack_type=attack_type,
        severity=severity,
        title=title,
        description=description,
        source_ip=source_ip or (ordered_logs[0].src_ip if ordered_logs else None),
        destination_ip=destination_ip or (ordered_logs[-1].dst_ip if ordered_logs else None),
        affected_host=affected_host or (ordered_logs[-1].hostname if ordered_logs else None),
        affected_hosts=hosts,
        related_log_ids=[log.log_id for log in ordered_logs if log.log_id],
        event_count=len(ordered_logs),
        time_window=window,
        mitre_attack=mitre_attack or [],
        event_chain=event_chain,
        stages=stage_names,
        stage_progression=stage_progression,
        recommended_action=recommended_action,
        metadata=metadata or {},
    )