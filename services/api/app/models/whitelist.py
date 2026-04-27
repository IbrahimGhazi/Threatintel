import uuid
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class WhitelistEntry(Base):
    __tablename__ = "whitelist_entries"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entry_type      = Column(Text, nullable=False)      # ip, cidr, hostname, rule_name, indicator_value
    value           = Column(Text, nullable=False)
    scope_rule      = Column(Text, nullable=True)        # restrict to specific rule, NULL = all
    reason          = Column(Text, nullable=True)
    created_by      = Column(Text, nullable=False, default="system")
    expires_at      = Column(DateTime(timezone=True), nullable=True)
    enabled         = Column(Boolean, nullable=False, default=True)
    source_alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True)
    created_at      = Column(DateTime(timezone=True), nullable=False, default=func.now())
    updated_at      = Column(DateTime(timezone=True), nullable=False, default=func.now())
