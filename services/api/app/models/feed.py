import uuid
from sqlalchemy import BigInteger, Boolean, Column, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base


class Feed(Base):
    __tablename__ = "feeds"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name            = Column(Text, nullable=False, unique=True)
    display_name    = Column(Text, nullable=False)
    description     = Column(Text)
    feed_type       = Column(Text, nullable=False)
    enabled         = Column(Boolean, nullable=False, default=True)
    url             = Column(Text)
    poll_interval   = Column(Integer, nullable=False, default=3600)
    last_run_at     = Column(DateTime(timezone=True))
    last_success_at = Column(DateTime(timezone=True))
    last_error      = Column(Text)
    last_error_at   = Column(DateTime(timezone=True))
    total_ingested  = Column(BigInteger, nullable=False, default=0)
    config          = Column(JSONB, nullable=False, default=dict)
    created_at      = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at      = Column(DateTime(timezone=True), nullable=False, default=func.now())
