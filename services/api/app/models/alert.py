import uuid
from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from app.database import Base

# Match the enum types declared in 01_schema.sql (create_type=False = already exist in DB)
_alert_status = Enum(
    "open", "acknowledged", "resolved", "false_positive",
    name="alert_status", create_type=False,
)
_severity_level = Enum(
    "critical", "high", "medium", "low", "info",
    name="severity_level", create_type=False,
)
_indicator_type = Enum(
    "ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "sha512",
    "email", "filename", "mutex", "registry_key", "user_agent",
    name="indicator_type", create_type=False,
)


class Alert(Base):
    __tablename__ = "alerts"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title           = Column(Text, nullable=False)
    description     = Column(Text)
    severity        = Column(_severity_level, nullable=False)
    status          = Column(_alert_status, nullable=False, default="open")
    indicator_id    = Column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="SET NULL"),
                             nullable=True, index=True)
    indicator_value = Column(Text)
    indicator_type  = Column(_indicator_type, nullable=True)
    rule_name       = Column(Text)
    source_service  = Column(Text, nullable=False, default="correlation")
    log_entry_id    = Column(UUID(as_uuid=True), nullable=True)
    context         = Column(JSONB, nullable=False, default=dict)
    created_at      = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at      = Column(DateTime(timezone=True), nullable=False, default=func.now())
    acknowledged_at = Column(DateTime(timezone=True))
    acknowledged_by = Column(Text)
    resolved_at     = Column(DateTime(timezone=True))
    notes           = Column(Text)
    incident_id     = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"),
                             nullable=True, index=True)

    indicator = relationship("Indicator", back_populates="alerts", lazy="noload")
    incident  = relationship("Incident", back_populates="alerts", lazy="noload")
