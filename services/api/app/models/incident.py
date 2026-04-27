import uuid
from sqlalchemy import Column, DateTime, Enum, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import relationship
from app.database import Base

_incident_status = Enum(
    "open", "investigating", "resolved", "closed",
    name="incident_status", create_type=False,
)
_severity_level = Enum(
    "critical", "high", "medium", "low", "info",
    name="severity_level", create_type=False,
)


class Incident(Base):
    __tablename__ = "incidents"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title         = Column(Text, nullable=False)
    description   = Column(Text)
    severity      = Column(_severity_level, nullable=False, default="medium")
    status        = Column(_incident_status, nullable=False, default="open")
    source_ip     = Column(Text)
    attack_type   = Column(Text)
    mitre_tactics = Column(ARRAY(Text), nullable=False, default=list)
    total_events  = Column(Integer, nullable=False, default=0)
    first_seen    = Column(DateTime(timezone=True), nullable=False, default=func.now())
    last_seen     = Column(DateTime(timezone=True), nullable=False, default=func.now())
    created_at    = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at    = Column(DateTime(timezone=True), nullable=False, default=func.now())

    alerts = relationship("Alert", back_populates="incident", lazy="noload")
