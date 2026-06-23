"""
Approval Service - Guardrail system for dangerous operations

Implements approval workflows for high-impact actions that require operator supervision.
Detects dangerous commands and routes them through an approval queue.
"""
import re
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import ApprovalRequest, User, Target, Scan
from app.services.audit_service import AuditService


# Patterns that indicate dangerous/destructive operations
DANGEROUS_PATTERNS = [
    # SQL injection attempts
    r"(DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE|UPDATE\s+\w+\s+SET)",
    # Command injection
    r"(rm\s+-rf|mkfs|dd\s+if=|:\(\)\s*\{)",
    # Privilege escalation
    r"(sudo\s+|chmod\s+777|chown\s+root)",
    # Out-of-scope indicators
    r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\.local|\.lan|\.internal)",
    # Private IP ranges
    r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",
    # Sensitive file access
    r"(/etc/passwd|/etc/shadow|\.ssh/|\.aws/credentials)",
]

# Request types that always require approval
ALWAYS_REQUIRE_APPROVAL = [
    "deep_scan",  # Deep scans are resource-intensive
    "ai_hunt",  # AI-powered hunting can be expensive
    "bulk_scan",  # Scanning multiple targets at once
    "export_raw_data",  # Exporting raw scan data
]

# Request types that require approval only for certain conditions
CONDITIONAL_APPROVAL = [
    "scan",  # Requires approval if target is high-risk or scan is deep
    "scanner_run",  # Requires approval for certain dangerous scanners
]


class ApprovalService:
    """Service for managing approval workflows"""
    
    @staticmethod
    def is_dangerous_action(payload: dict[str, Any], request_type: str) -> tuple[bool, str]:
        """
        Check if an action is dangerous and requires approval.
        
        Args:
            payload: Action payload (scan config, scanner params, etc.)
            request_type: Type of request
        
        Returns:
            Tuple of (is_dangerous, reason)
        """
        # Always require approval for certain request types
        if request_type in ALWAYS_REQUIRE_APPROVAL:
            return True, f"Request type '{request_type}' always requires approval"
        
        # Check payload for dangerous patterns
        payload_str = str(payload).lower()
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return True, f"Payload matches dangerous pattern: {pattern}"
        
        # Check for private IP targets
        target = payload.get("target", "")
        if target:
            private_ip_pattern = r"(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.0\.0\.1|localhost)"
            if re.search(private_ip_pattern, target):
                return True, f"Target contains private/internal IP: {target}"
        
        # Check for deep scans
        scan_type = payload.get("scan_type", "")
        if scan_type == "deep":
            return True, "Deep scans require approval due to resource intensity"
        
        return False, ""
    
    @staticmethod
    async def create_request(
        db: AsyncSession,
        requestor_id: str,
        request_type: str,
        payload: dict[str, Any],
        target_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        reason: Optional[str] = None,
        expires_in_minutes: int = 60,
    ) -> ApprovalRequest:
        """
        Create a new approval request.
        
        Args:
            db: Database session
            requestor_id: ID of user requesting approval
            request_type: Type of request (scan, scanner_run, ai_hunt, etc.)
            payload: Request details
            target_id: Optional target ID
            scan_id: Optional scan ID
            reason: Why this needs approval
            expires_in_minutes: How long until request expires
        
        Returns:
            Created ApprovalRequest
        """
        expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        
        request = ApprovalRequest(
            request_type=request_type,
            requestor_id=requestor_id,
            target_id=target_id,
            scan_id=scan_id,
            payload=payload,
            reason=reason,
            status="pending",
            expires_at=expires_at,
        )
        db.add(request)
        await db.commit()
        await db.refresh(request)
        
        # Log the request
        await AuditService.log_action(
            db, requestor_id, "approval.request", "approval", str(request.id),
            {"request_type": request_type, "target_id": target_id}
        )
        
        return request
    
    @staticmethod
    async def get_request(db: AsyncSession, request_id: str) -> Optional[ApprovalRequest]:
        """Get an approval request by ID"""
        result = await db.execute(
            select(ApprovalRequest).where(ApprovalRequest.id == request_id)
        )
        return result.scalar_one_or_none()
    
    @staticmethod
    async def list_pending_requests(
        db: AsyncSession,
        reviewer_id: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[ApprovalRequest]:
        """
        List pending approval requests.
        
        Args:
            db: Database session
            reviewer_id: Optional filter by reviewer (for assigned requests)
            skip: Pagination offset
            limit: Maximum results
        
        Returns:
            List of pending ApprovalRequests
        """
        query = select(ApprovalRequest).where(ApprovalRequest.status == "pending")
        
        if reviewer_id:
            # Show requests that need review (not requested by this user)
            query = query.where(ApprovalRequest.requestor_id != reviewer_id)
        
        query = query.order_by(ApprovalRequest.requested_at.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()
    
    @staticmethod
    async def review_request(
        db: AsyncSession,
        request_id: str,
        reviewer_id: str,
        decision: str,  # "approved" or "rejected"
        comment: Optional[str] = None,
    ) -> ApprovalRequest:
        """
        Review an approval request.
        
        Args:
            db: Database session
            request_id: ID of the request
            reviewer_id: ID of the reviewer
            decision: "approved" or "rejected"
            comment: Optional review comment
        
        Returns:
            Updated ApprovalRequest
        
        Raises:
            ValueError: If request not found, already reviewed, or expired
        """
        request = await ApprovalService.get_request(db, request_id)
        
        if not request:
            raise ValueError("Approval request not found")
        
        if request.status != "pending":
            raise ValueError(f"Request already {request.status}")
        
        # Check expiration
        if request.expires_at and datetime.utcnow() > request.expires_at:
            request.status = "expired"
            await db.commit()
            raise ValueError("Request has expired")
        
        # Cannot review own request
        if request.requestor_id == reviewer_id:
            raise ValueError("Cannot review your own approval request")
        
        request.reviewer_id = reviewer_id
        request.status = decision
        request.review_comment = comment
        request.reviewed_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(request)
        
        # Log the review
        await AuditService.log_action(
            db, reviewer_id, "approval.review", "approval", request_id,
            {"decision": decision, "comment": comment}
        )
        
        return request
    
    @staticmethod
    async def cancel_request(db: AsyncSession, request_id: str, user_id: str) -> ApprovalRequest:
        """
        Cancel an approval request (by requestor).
        
        Args:
            db: Database session
            request_id: ID of the request
            user_id: ID of the user cancelling
        
        Returns:
            Updated ApprovalRequest
        """
        request = await ApprovalService.get_request(db, request_id)
        
        if not request:
            raise ValueError("Approval request not found")
        
        if request.requestor_id != user_id:
            raise ValueError("Only the requestor can cancel their request")
        
        if request.status != "pending":
            raise ValueError(f"Cannot cancel request with status: {request.status}")
        
        request.status = "rejected"
        request.review_comment = "Cancelled by requestor"
        request.reviewed_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(request)
        
        return request
    
    @staticmethod
    async def is_approved(db: AsyncSession, request_id: str) -> bool:
        """Check if a request has been approved"""
        request = await ApprovalService.get_request(db, request_id)
        if not request:
            return False
        return request.status == "approved"
    
    @staticmethod
    async def cleanup_expired(db: AsyncSession) -> int:
        """
        Mark expired requests and return count.
        
        Returns:
            Number of requests marked as expired
        """
        now = datetime.utcnow()
        query = select(ApprovalRequest).where(
            ApprovalRequest.status == "pending",
            ApprovalRequest.expires_at < now
        )
        result = await db.execute(query)
        expired = result.scalars().all()
        
        for request in expired:
            request.status = "expired"
        
        await db.commit()
        return len(expired)
    
    @staticmethod
    async def get_user_requests(
        db: AsyncSession,
        user_id: str,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[ApprovalRequest]:
        """Get approval requests for a user (as requestor)"""
        query = select(ApprovalRequest).where(ApprovalRequest.requestor_id == user_id)
        
        if status:
            query = query.where(ApprovalRequest.status == status)
        
        query = query.order_by(ApprovalRequest.requested_at.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()


class GuardrailService:
    """Service for enforcing safety guardrails"""
    
    @staticmethod
    def check_network_guardrails(target: str, allowed_private: bool = False) -> tuple[bool, str]:
        """
        Check if target passes network guardrails.
        
        Args:
            target: Target domain/IP
            allowed_private: Whether private IPs are explicitly allowed
        
        Returns:
            Tuple of (is_allowed, reason)
        """
        import ipaddress
        
        # Check for localhost
        if target in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:
            return False, "localhost targets are not allowed"
        
        # Check for local domains
        if target.endswith((".local", ".lan", ".internal", ".home")):
            return False, "local domain targets are not allowed"
        
        # Check for private IP ranges
        try:
            ip = ipaddress.ip_address(target)
            if ip.is_private and not allowed_private:
                return False, f"private IP range not allowed: {target}"
        except ValueError:
            # Not an IP address, treat as domain (allowed)
            pass
        
        return True, ""
    
    @staticmethod
    def redact_secrets(text: str) -> str:
        """
        Redact secrets from text (prompts, logs, artifacts).
        
        Args:
            text: Text to redact
        
        Returns:
            Redacted text
        """
        # API keys and tokens
        patterns = [
            (r"(api[_-]?key|token|secret|password|auth)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{20,})['\"]?", r"\1: [REDACTED]"),
            (r"Bearer\s+([a-zA-Z0-9_\-\.]+)", "Bearer [REDACTED]"),
            (r"Basic\s+([a-zA-Z0-9_\-\.]+)", "Basic [REDACTED]"),
            # AWS keys
            (r"AKIA[0-9A-Z]{16}", "[REDACTED_AWS_KEY]"),
            # Credit cards (basic pattern)
            (r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b", "[REDACTED_CC]"),
            # SSN
            (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
        ]
        
        for pattern, replacement in patterns:
            text = re.sub(pattern, replacement, text, flags=re.IGNORECASE)
        
        return text
    
    @staticmethod
    async def validate_scan_request(
        db: AsyncSession,
        user_id: str,
        target_id: str,
        scan_type: str,
        payload: dict[str, Any],
    ) -> tuple[bool, str, Optional[str]]:
        """
        Validate a scan request against all guardrails.
        
        Args:
            db: Database session
            user_id: User ID
            target_id: Target ID
            scan_type: Scan type
            payload: Scan configuration
        
        Returns:
            Tuple of (is_allowed, reason, approval_request_id)
            If approval is needed, approval_request_id will be set
        """
        # Get target
        result = await db.execute(select(Target).where(Target.id == target_id))
        target = result.scalar_one_or_none()
        
        if not target:
            return False, "Target not found", None
        
        # Check network guardrails
        allowed, reason = GuardrailService.check_network_guardrails(target.domain)
        if not allowed:
            return False, reason, None
        
        # Check if approval is needed
        is_dangerous, dangerous_reason = ApprovalService.is_dangerous_action(
            {**payload, "scan_type": scan_type, "target": target.domain},
            "scan"
        )
        
        if is_dangerous:
            # Create approval request
            request = await ApprovalService.create_request(
                db,
                requestor_id=user_id,
                request_type="scan",
                payload={**payload, "scan_type": scan_type, "target_id": target_id},
                target_id=target_id,
                reason=dangerous_reason,
            )
            return False, f"Approval required: {dangerous_reason}", str(request.id)
        
        return True, "", None
