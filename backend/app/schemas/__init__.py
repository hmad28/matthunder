"""
Pydantic schemas for API validation
"""
from datetime import datetime
from typing import Optional, Any
from uuid import UUID
from pydantic import AliasChoices, BaseModel, EmailStr, Field, ConfigDict


# ============ User Schemas ============

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)


class UserResponse(UserBase):
    id: UUID
    is_active: bool
    is_superuser: bool
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    user_id: Optional[UUID] = None


# ============ Target Schemas ============

class TargetBase(BaseModel):
    domain: str = Field(..., max_length=255)
    notes: Optional[str] = None
    scope: Optional[dict[str, Any]] = None


class TargetCreate(TargetBase):
    pass


class TargetUpdate(BaseModel):
    domain: Optional[str] = Field(None, max_length=255)
    notes: Optional[str] = None
    scope: Optional[dict[str, Any]] = None


class TargetResponse(TargetBase):
    id: UUID
    created_by: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ Scan Schemas ============

class ScanBase(BaseModel):
    scan_type: str = Field(..., max_length=50)
    speed: str = Field(default="standard", pattern="^(low|standard|fast)$")
    metadata: Optional[dict[str, Any]] = Field(default=None, validation_alias=AliasChoices("metadata_", "metadata"))


class ScanCreate(ScanBase):
    target_id: UUID


class ScanResponse(ScanBase):
    id: UUID
    target_id: UUID
    status: str
    celery_task_id: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: Optional[UUID] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class ScanStatus(BaseModel):
    id: UUID
    status: str
    target_id: UUID
    scan_type: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


# ============ Finding Schemas ============

class FindingBase(BaseModel):
    scanner: str = Field(..., max_length=50)
    severity: Optional[str] = Field(None, pattern="^(critical|high|medium|low|info)$")
    category: Optional[str] = Field(None, max_length=100)
    title: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    url: Optional[str] = None
    source_url: Optional[str] = None
    evidence: Optional[str] = None
    http_code: Optional[int] = None
    status: str = Field(default="new", pattern="^(new|confirmed|false_positive|fixed)$")
    cve_id: Optional[str] = Field(None, max_length=50)
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    remediation: Optional[str] = None
    metadata: Optional[dict[str, Any]] = Field(default=None, validation_alias=AliasChoices("metadata_", "metadata"))


class FindingCreate(FindingBase):
    scan_id: UUID


class FindingUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(new|confirmed|false_positive|fixed)$")
    severity: Optional[str] = Field(None, pattern="^(critical|high|medium|low|info)$")


class FindingResponse(FindingBase):
    id: UUID
    scan_id: UUID
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class FindingStats(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int


# ============ ScanLog Schemas ============

class ScanLogCreate(BaseModel):
    scan_id: UUID
    level: str = Field(..., pattern="^(info|warn|error|success)$")
    message: str


class ScanLogResponse(BaseModel):
    id: int
    scan_id: UUID
    level: str
    message: str
    timestamp: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ Report Schemas ============

class ReportResponse(BaseModel):
    id: UUID
    scan_id: UUID
    report_type: str
    file_path: str
    file_size: Optional[int] = None
    generated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ Scanner Schemas ============

class ScannerInfo(BaseModel):
    name: str
    display_name: str
    description: str
    category: str
    is_active: bool


class ScannerRunRequest(BaseModel):
    target: str
    config: Optional[dict[str, Any]] = None


class ScannerRunResponse(BaseModel):
    scan_id: UUID
    scanner: str
    status: str
    message: str


# ============ Pipeline Schemas ============

class PipelineRunRequest(BaseModel):
    target_id: UUID
    speed: str = Field(default="standard", pattern="^(low|standard|fast)$")
    phases: Optional[list[str]] = None  # Specific phases to run


class PipelineStatus(BaseModel):
    scan_id: UUID
    current_phase: str
    completed_phases: list[str]
    status: str
    progress: float  # 0.0 to 1.0


# ============ AI Schemas ============

class AIProviderInfo(BaseModel):
    name: str
    configured: bool
    default_model: str
    available_models: list[str]


class AIAnalyzeRequest(BaseModel):
    prompt: str
    provider: Optional[str] = None
    model: Optional[str] = None
    scan_id: Optional[UUID] = None


class AIAnalyzeResponse(BaseModel):
    id: UUID
    provider: str
    model: str
    response: dict[str, Any]
    tokens_used: Optional[int] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class AIHuntRequest(BaseModel):
    target_id: UUID
    provider: Optional[str] = None
    model: Optional[str] = None
    focus: Optional[str] = None  # Specific vulnerability types to focus on


# ============ WebSocket Schemas ============

class WSMessage(BaseModel):
    type: str  # log, status, error, complete
    data: dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============ Audit Log Schemas ============

class AuditLogResponse(BaseModel):
    id: UUID
    user_id: Optional[UUID] = None
    action: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    details: Optional[dict[str, Any]] = None
    ip_address: Optional[str] = None
    status: str
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ Approval Request Schemas ============

class ApprovalRequestCreate(BaseModel):
    request_type: str = Field(..., max_length=50)
    target_id: Optional[UUID] = None
    scan_id: Optional[UUID] = None
    payload: dict[str, Any]
    reason: Optional[str] = None
    expires_in_minutes: int = Field(default=60, ge=5, le=1440)  # 5 min to 24 hours


class ApprovalRequestResponse(BaseModel):
    id: UUID
    request_type: str
    requestor_id: UUID
    reviewer_id: Optional[UUID] = None
    target_id: Optional[UUID] = None
    scan_id: Optional[UUID] = None
    payload: dict[str, Any]
    reason: Optional[str] = None
    status: str
    review_comment: Optional[str] = None
    requested_at: datetime
    reviewed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    model_config = ConfigDict(from_attributes=True)


class ApprovalReview(BaseModel):
    status: str = Field(..., pattern="^(approved|rejected)$")
    comment: Optional[str] = None


# ============ Evidence Schemas ============

class EvidenceResponse(BaseModel):
    id: UUID
    scan_id: UUID
    finding_id: Optional[UUID] = None
    scanner: Optional[str] = None
    file_path: str
    file_name: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    content_type: Optional[str] = None
    metadata: Optional[dict[str, Any]] = Field(default=None, validation_alias=AliasChoices("metadata_", "metadata"))
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ Scope Rule Schemas ============

class ScopeRuleCreate(BaseModel):
    rule_type: str = Field(..., pattern="^(domain|path|ip_range|regex)$")
    pattern: str = Field(..., max_length=500)
    is_allowed: bool = True
    description: Optional[str] = None


class ScopeRuleResponse(ScopeRuleCreate):
    id: UUID
    target_id: UUID
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ API Key Schemas ============

class APIKeyCreate(BaseModel):
    name: str = Field(..., max_length=100)
    scopes: Optional[list[str]] = None
    expires_in_days: Optional[int] = Field(None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    id: UUID
    name: str
    scopes: Optional[list[str]] = None
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    is_active: bool
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class APIKeyCreateResponse(APIKeyResponse):
    """Response includes the actual key only on creation"""
    key: str  # Only returned once on creation


# ============ Target Verification Schemas ============

class TargetVerificationResponse(BaseModel):
    id: UUID
    target_id: UUID
    status: str
    method: Optional[str] = None
    verified_at: Optional[datetime] = None
    details: Optional[dict[str, Any]] = None
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


class TargetVerificationRequest(BaseModel):
    method: str = Field(default="dns", pattern="^(dns|http|manual)$")


# ============ Rate Limit Schemas ============

class RateLimitCreate(BaseModel):
    requests_per_second: int = Field(default=10, ge=1, le=1000)
    burst: int = Field(default=20, ge=1, le=10000)
    delay_between_requests: float = Field(default=0.1, ge=0.0, le=60.0)


class RateLimitResponse(RateLimitCreate):
    id: UUID
    target_id: UUID
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ Scan Template Schemas ============

class ScanTemplateCreate(BaseModel):
    name: str = Field(..., max_length=100)
    description: Optional[str] = None
    scan_type: str = Field(..., max_length=50)
    speed: str = Field(default="standard", pattern="^(low|standard|fast)$")
    config: dict[str, Any]


class ScanTemplateResponse(ScanTemplateCreate):
    id: UUID
    is_active: bool
    created_by: Optional[UUID] = None
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ Finding Comment Schemas ============

class FindingCommentCreate(BaseModel):
    comment: str


class FindingCommentResponse(BaseModel):
    id: UUID
    finding_id: UUID
    user_id: Optional[UUID] = None
    comment: str
    created_at: datetime
    updated_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# ============ Finding Relationship Schemas ============

class FindingRelationshipCreate(BaseModel):
    related_finding_id: UUID
    relationship_type: str = Field(..., pattern="^(related|attack_chain|prerequisite)$")
    description: Optional[str] = None


class FindingRelationshipResponse(FindingRelationshipCreate):
    id: UUID
    finding_id: UUID
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)
