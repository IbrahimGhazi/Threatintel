import uuid
from sqlalchemy import BigInteger, Column, DateTime, Enum, Integer, SmallInteger, String, Text, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from app.database import Base

_sandbox_status = Enum(
    "pending", "running", "completed", "failed", "timeout",
    name="sandbox_status", create_type=False,
)


class SandboxResult(Base):
    __tablename__ = "sandbox_results"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    file_sha256     = Column(Text, nullable=False, unique=True)
    file_md5        = Column(Text)
    file_sha1       = Column(Text)
    file_name       = Column(Text)
    file_size       = Column(BigInteger)
    file_type       = Column(Text)
    status          = Column(_sandbox_status, nullable=False, default="pending")
    verdict         = Column(Text)
    malware_score   = Column(SmallInteger)
    malware_family  = Column(Text)
    sandbox_task_id = Column(Text)
    sandbox_engine  = Column(Text, nullable=False, default="cape")
    report          = Column(JSONB, nullable=False, default=dict)
    extracted_iocs  = Column(JSONB, nullable=False, default=dict)
    submitted_at    = Column(DateTime(timezone=True), nullable=False, default=func.now())
    started_at      = Column(DateTime(timezone=True))
    completed_at    = Column(DateTime(timezone=True))
    error           = Column(Text)
