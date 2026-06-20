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
