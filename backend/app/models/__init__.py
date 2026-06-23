"""
SQLAlchemy models for matthunder - SQLite compatible
"""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Text, Boolean, Integer, Float, DateTime, 
    ForeignKey, JSON, Index, UniqueConstraint
)
from sqlalchemy.orm import relationship
from app.database import Base


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    """User model for authentication"""
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    targets = relationship("Target", back_populates="owner", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")


class Target(Base):
    """Target domain model"""
    __tablename__ = "targets"
    __table_args__ = (
        UniqueConstraint('domain', 'created_by', name='uq_target_domain_owner'),
    )
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain = Column(String(255), nullable=False, index=True)
    notes = Column(Text)
    scope = Column(JSON)  # Bug bounty scope data - using JSON instead of JSONB for SQLite
    created_by = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    owner = relationship("User", back_populates="targets")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Scan(Base):
    """Scan execution model"""
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_type = Column(String(50), nullable=False, index=True)
    status = Column(String(20), default="pending", index=True)
    speed = Column(String(20), default="standard")
    celery_task_id = Column(String(255))
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    metadata_ = Column("metadata", JSON)  # Using JSON instead of JSONB
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    owner = relationship("User", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    logs = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_scan_status_created', 'status', 'created_at'),
    )


class Finding(Base):
    """Vulnerability finding model"""
    __tablename__ = "findings"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    scanner = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), index=True)
    category = Column(String(100))
    title = Column(String(255))
    description = Column(Text)
    url = Column(Text)
    source_url = Column(Text)
    evidence = Column(Text)
    http_code = Column(Integer)
    status = Column(String(20), default="new")
    cve_id = Column(String(50))
    cvss_score = Column(Float)
    remediation = Column(Text)
    metadata_ = Column("metadata", JSON)  # Using JSON instead of JSONB
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")


class ScanLog(Base):
    """Scan log entries for real-time streaming"""
    __tablename__ = "scan_logs"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    level = Column(String(10))
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    scan = relationship("Scan", back_populates="logs")


class Report(Base):
    """Generated report model"""
    __tablename__ = "reports"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = Column(String(50))
    file_path = Column(String(500))
    file_size = Column(Integer)
    generated_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")


class ScannerRegistry(Base):
    """Scanner registry for dynamic loading"""
    __tablename__ = "scanner_registry"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(50), unique=True, nullable=False)
    display_name = Column(String(100))
    description = Column(Text)
    category = Column(String(50))
    is_active = Column(Boolean, default=True)
    config_schema = Column(JSON)  # Using JSON instead of JSONB
    created_at = Column(DateTime, default=datetime.utcnow)


class AIAnalysis(Base):
    """AI analysis results"""
    __tablename__ = "ai_analyses"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(50))
    model = Column(String(100))
    prompt = Column(Text)
    response = Column(JSON)  # Using JSON instead of JSONB
    tokens_used = Column(Integer)
    cost_usd = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)


# ============ Enhanced Models for Platform Features ============

class AuditLog(Base):
    """Audit trail for all system actions"""
    __tablename__ = "audit_logs"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action = Column(String(100), nullable=False, index=True)  # e.g., "scan.create", "finding.update"
    resource_type = Column(String(50), index=True)  # e.g., "scan", "finding", "target"
    resource_id = Column(String(36), index=True)
    details = Column(JSON)  # Additional context
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    status = Column(String(20), default="success")  # success, failure
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_audit_user_action', 'user_id', 'action'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
    )


class ApprovalRequest(Base):
    """Approval workflow for dangerous operations"""
    __tablename__ = "approval_requests"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    request_type = Column(String(50), nullable=False, index=True)  # scan, scanner_run, ai_hunt
    requestor_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    reviewer_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), index=True)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    payload = Column(JSON, nullable=False)  # Request details (scan config, scanner params, etc.)
    reason = Column(Text)  # Why this needs approval
    status = Column(String(20), default="pending", index=True)  # pending, approved, rejected, expired
    review_comment = Column(Text)
    requested_at = Column(DateTime, default=datetime.utcnow)
    reviewed_at = Column(DateTime)
    expires_at = Column(DateTime)
    
    # Relationships
    requestor = relationship("User", foreign_keys=[requestor_id])
    reviewer = relationship("User", foreign_keys=[reviewer_id])
    target = relationship("Target")
    scan = relationship("Scan")
    
    __table_args__ = (
        Index('idx_approval_status_requested', 'status', 'requested_at'),
    )


class Evidence(Base):
    """Evidence files collected during scans"""
    __tablename__ = "evidence"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), index=True)
    scanner = Column(String(50), index=True)
    file_path = Column(String(500), nullable=False)
    file_name = Column(String(255))
    file_type = Column(String(50))  # screenshot, http_response, source_code, etc.
    file_size = Column(Integer)
    file_hash = Column(String(64))  # SHA-256 hash for deduplication
    content_type = Column(String(100))  # MIME type
    metadata_ = Column("metadata", JSON)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    scan = relationship("Scan")
    finding = relationship("Finding")
    
    __table_args__ = (
        Index('idx_evidence_scan_scanner', 'scan_id', 'scanner'),
    )


class ScopeRule(Base):
    """Scope rules for targets (allowed/disallowed patterns)"""
    __tablename__ = "scope_rules"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_type = Column(String(20), nullable=False)  # domain, path, ip_range, regex
    pattern = Column(String(500), nullable=False)
    is_allowed = Column(Boolean, default=True)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    target = relationship("Target")
    
    __table_args__ = (
        Index('idx_scope_target_type', 'target_id', 'rule_type'),
    )


class RefreshToken(Base):
    """JWT refresh tokens for session management"""
    __tablename__ = "refresh_tokens"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hash of token
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime)
    ip_address = Column(String(45))
    user_agent = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User")
    
    __table_args__ = (
        Index('idx_refresh_user_expires', 'user_id', 'expires_at'),
    )


class APIKey(Base):
    """API keys for service accounts (CLI, bot, integrations)"""
    __tablename__ = "api_keys"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)  # Human-readable name
    key_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hash of key
    scopes = Column(JSON)  # List of permitted scopes/actions
    expires_at = Column(DateTime)
    last_used_at = Column(DateTime)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relationships
    user = relationship("User")
    
    __table_args__ = (
        Index('idx_apikey_user_active', 'user_id', 'is_active'),
    )


class TargetVerification(Base):
    """Target verification records (DNS, HTTP probe)"""
    __tablename__ = "target_verifications"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(20), nullable=False)  # pending, verified, failed
    method = Column(String(50))  # dns, http, manual
    verified_at = Column(DateTime)
    details = Column(JSON)  # Verification results
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    target = relationship("Target")


class RateLimit(Base):
    """Rate limit configuration per target"""
    __tablename__ = "rate_limits"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, unique=True)
    requests_per_second = Column(Integer, default=10)
    burst = Column(Integer, default=20)
    delay_between_requests = Column(Float, default=0.1)  # seconds
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    target = relationship("Target")


class ScanTemplate(Base):
    """Predefined scan configurations"""
    __tablename__ = "scan_templates"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text)
    scan_type = Column(String(50), nullable=False)
    speed = Column(String(20), default="standard")
    config = Column(JSON, nullable=False)  # Scanner config, phases, etc.
    is_active = Column(Boolean, default=True)
    created_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    creator = relationship("User")


class FindingComment(Base):
    """Comments/notes on findings"""
    __tablename__ = "finding_comments"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"))
    comment = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    finding = relationship("Finding")
    user = relationship("User")


class FindingRelationship(Base):
    """Relationships between findings (attack chains, related vulns)"""
    __tablename__ = "finding_relationships"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    related_finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False)  # related, attack_chain, prerequisite
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    finding = relationship("Finding", foreign_keys=[finding_id])
    related_finding = relationship("Finding", foreign_keys=[related_finding_id])
    
    __table_args__ = (
        UniqueConstraint('finding_id', 'related_finding_id', 'relationship_type', name='uq_finding_relationship'),
    )


class MemoryContext(Base):
    """Persistent context for AI reasoning and cross-target pattern learning"""
    __tablename__ = "memory_contexts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    scan_id = Column(String(36), ForeignKey("scans.id", ondelete="SET NULL"))
    context_type = Column(String(50), nullable=False, index=True)
    content = Column(JSON)  # Context content (JSON)
    metadata_ = Column("metadata", JSON)  # Additional metadata
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    target = relationship("Target")
    scan = relationship("Scan")
    
    __table_args__ = (
        Index('idx_memory_context_target_scan', 'target_id', 'scan_id'),
        Index('idx_memory_context_type', 'context_type'),
    )
