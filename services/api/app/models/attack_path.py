"""
ORM models for the Attack Path & Fan-Out Analysis Engine.

Backed by `infra/postgres/init/15_attack_paths.sql`. Enums use
`create_type=False` because they're declared by the SQL init script.
"""
import uuid

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Integer, Numeric,
    SmallInteger, String, Text, func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID

from app.database import Base


_topology_run_status = Enum(
    "pending", "parsing", "loading", "analyzing", "completed", "failed",
    name="topology_run_status", create_type=False,
)
_attack_path_finding_kind = Enum(
    "path", "fanout",
    name="attack_path_finding_kind", create_type=False,
)
_attack_path_finding_status = Enum(
    "open", "acknowledged", "suppressed",
    name="attack_path_finding_status", create_type=False,
)
_severity_level = Enum(
    "critical", "high", "medium", "low", "info",
    name="severity_level", create_type=False,
)


class TopologyRun(Base):
    __tablename__ = "topology_runs"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    status            = Column(_topology_run_status, nullable=False, default="pending")
    started_at        = Column(DateTime(timezone=True), nullable=False, default=func.now())
    finished_at       = Column(DateTime(timezone=True))
    duration_ms       = Column(Integer)
    device_count      = Column(Integer, nullable=False, default=0)
    neo4j_node_count  = Column(Integer, nullable=False, default=0)
    neo4j_rel_count   = Column(Integer, nullable=False, default=0)
    findings_count    = Column(Integer, nullable=False, default=0)
    ir_snapshot       = Column(JSONB, nullable=False, default=dict)
    parse_warnings    = Column(JSONB, nullable=False, default=list)
    error_message     = Column(Text)
    weights           = Column(JSONB, nullable=False, default=dict)
    triggered_by      = Column(Text)
    created_at        = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at        = Column(DateTime(timezone=True), nullable=False, default=func.now())


class TopologyConfigUpload(Base):
    __tablename__ = "topology_config_uploads"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id            = Column(UUID(as_uuid=True),
                               ForeignKey("topology_runs.id", ondelete="CASCADE"),
                               nullable=True, index=True)
    vendor            = Column(Text, nullable=False)
    role              = Column(Text, nullable=False, default="unknown")
    device_id         = Column(Text)
    hostname          = Column(Text)
    original_filename = Column(Text, nullable=False)
    sha256            = Column(Text, nullable=False, index=True)
    size_bytes        = Column(Integer, nullable=False)
    stored_path       = Column(Text, nullable=False)
    parse_status      = Column(Text, nullable=False, default="pending")
    parse_error       = Column(Text)
    uploaded_at       = Column(DateTime(timezone=True), nullable=False, default=func.now())


class AttackPathFinding(Base):
    __tablename__ = "attack_path_findings"

    id                  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fingerprint         = Column(Text, nullable=False, unique=True)
    kind                = Column(_attack_path_finding_kind, nullable=False)
    severity            = Column(_severity_level, nullable=False)
    score               = Column(Numeric(5, 2), nullable=False)
    status              = Column(_attack_path_finding_status, nullable=False, default="open")

    asset_ip            = Column(INET)
    asset_hostname      = Column(Text)
    asset_criticality   = Column(Text)
    ingress             = Column(Text, nullable=False)
    hops                = Column(SmallInteger)

    path_json           = Column(JSONB)
    fanout_json         = Column(JSONB)
    rules_cited         = Column(JSONB, nullable=False, default=list)
    score_breakdown     = Column(JSONB, nullable=False, default=dict)

    first_seen_run_id   = Column(UUID(as_uuid=True),
                                 ForeignKey("topology_runs.id", ondelete="SET NULL"))
    last_seen_run_id    = Column(UUID(as_uuid=True),
                                 ForeignKey("topology_runs.id", ondelete="SET NULL"),
                                 index=True)
    first_seen_at       = Column(DateTime(timezone=True), nullable=False, default=func.now())
    last_seen_at        = Column(DateTime(timezone=True), nullable=False, default=func.now())

    acknowledged_at     = Column(DateTime(timezone=True))
    acknowledged_by     = Column(Text)
    suppressed_at       = Column(DateTime(timezone=True))
    suppressed_by       = Column(Text)
    suppression_reason  = Column(Text)
    notes               = Column(Text)
    created_at          = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at          = Column(DateTime(timezone=True), nullable=False, default=func.now())


class AttackPathAsset(Base):
    __tablename__ = "attack_path_assets"

    ip            = Column(INET, primary_key=True)
    hostname      = Column(Text)
    criticality   = Column(Text, nullable=False)
    business_unit = Column(Text)
    notes         = Column(Text)
    created_by    = Column(Text)
    created_at    = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at    = Column(DateTime(timezone=True), nullable=False, default=func.now())
