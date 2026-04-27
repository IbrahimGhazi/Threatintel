import uuid
from sqlalchemy import Boolean, Column, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from app.database import Base


class LogEntry(Base):
    __tablename__ = "log_entries"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_type    = Column(Text, nullable=False)
    source_name    = Column(Text)
    source_ip      = Column(Text)           # device IP (INET stored as text for portability)
    raw_log        = Column(Text)
    parsed         = Column(JSONB, nullable=False, default=dict)
    extracted_iocs = Column(JSONB, nullable=False, default=dict)
    matched_iocs   = Column(JSONB, nullable=False, default=list)
    indicator_ids  = Column(ARRAY(UUID(as_uuid=True)), nullable=False, default=list)
    is_malicious   = Column(Boolean, nullable=False, default=False)
    log_timestamp  = Column(DateTime(timezone=True))
    processed_at   = Column(DateTime(timezone=True), nullable=False, default=func.now())
