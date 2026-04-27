"""
SQLAlchemy ORM models for indicators and their sources.
These mirror the PostgreSQL schema defined in infra/postgres/init/01_schema.sql.
"""
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, ForeignKey, Integer,
    SmallInteger, String, Text, ARRAY, func,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship

from app.database import Base

# Match enums in 01_schema.sql (create_type=False = already exist in DB)
_indicator_type = Enum(
    "ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "sha512",
    "email", "filename", "mutex", "registry_key", "user_agent",
    name="indicator_type", create_type=False,
)
_severity_level = Enum(
    "critical", "high", "medium", "low", "info",
    name="severity_level", create_type=False,
)


class Indicator(Base):
    __tablename__ = "indicators"

    id               = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    type             = Column(_indicator_type, nullable=False, index=True)
    value            = Column(Text, nullable=False)
    normalized_value = Column(Text, nullable=False)
    severity         = Column(_severity_level, nullable=False, default="medium")
    confidence       = Column(SmallInteger, nullable=False, default=50)
    reputation_score = Column(SmallInteger, nullable=False, default=0)
    first_seen       = Column(DateTime(timezone=True), nullable=False, default=func.now())
    last_seen        = Column(DateTime(timezone=True), nullable=False, default=func.now())
    active           = Column(Boolean, nullable=False, default=True)
    false_positive   = Column(Boolean, nullable=False, default=False)
    tags             = Column(ARRAY(Text), nullable=False, default=list)
    enrichment       = Column(JSONB, nullable=False, default=dict)
    metadata_        = Column("metadata", JSONB, nullable=False, default=dict)
    expires_at       = Column(DateTime(timezone=True), nullable=True)
    created_at       = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at       = Column(DateTime(timezone=True), nullable=False, default=func.now())

    sources   = relationship("IndicatorSource", back_populates="indicator",
                             cascade="all, delete-orphan", lazy="selectin")
    alerts    = relationship("Alert", back_populates="indicator", lazy="noload")

    def __repr__(self) -> str:
        return f"<Indicator type={self.type} value={self.value[:40]}>"


class IndicatorSource(Base):
    __tablename__ = "indicator_sources"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    indicator_id    = Column(UUID(as_uuid=True), ForeignKey("indicators.id", ondelete="CASCADE"),
                             nullable=False, index=True)
    source_name     = Column(Text, nullable=False)
    source_category = Column(Text, nullable=False, default="open_source")
    raw_data        = Column(JSONB, nullable=False, default=dict)
    first_seen      = Column(DateTime(timezone=True), nullable=False, default=func.now())
    last_seen       = Column(DateTime(timezone=True), nullable=False, default=func.now())
    confidence      = Column(SmallInteger, nullable=False, default=50)

    indicator = relationship("Indicator", back_populates="sources")
