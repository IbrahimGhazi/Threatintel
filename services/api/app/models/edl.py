import uuid
from sqlalchemy import Boolean, Column, DateTime, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from app.database import Base


class EDLConfig(Base):
    __tablename__ = "edl_configs"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name           = Column(Text, nullable=False, unique=True)
    slug           = Column(Text, nullable=False, unique=True)
    description    = Column(Text)
    indicator_type = Column(String(32), nullable=False)
    min_confidence = Column(SmallInteger, nullable=False, default=50)
    min_severity   = Column(String(16), nullable=False, default="medium")
    tags_filter    = Column(ARRAY(Text))
    max_age_days   = Column(Integer)
    format         = Column(Text, nullable=False, default="plain")
    enabled        = Column(Boolean, nullable=False, default=True)
    cached_count   = Column(Integer, nullable=False, default=0)
    last_built_at  = Column(DateTime(timezone=True))
    created_at     = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at     = Column(DateTime(timezone=True), nullable=False, default=func.now())
