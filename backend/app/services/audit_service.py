"""
Audit Service - Comprehensive audit trail for all system actions

Provides structured logging of all user actions, system events, and security-relevant operations.
"""
from datetime import datetime
from typing import Any, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import AuditLog, User


class AuditService:
    """Service for recording and querying audit logs"""
    
    @staticmethod
    async def log_action(
        db: AsyncSession,
        user_id: Optional[str],
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: str = "success"
    ) -> AuditLog:
        """
        Record an audit log entry.
        
        Args:
            db: Database session
            user_id: ID of the user performing the action (None for system actions)
            action: Action identifier (e.g., "scan.create", "finding.update", "auth.login")
            resource_type: Type of resource affected (e.g., "scan", "finding", "target")
            resource_id: ID of the specific resource
            details: Additional context/metadata
            ip_address: Client IP address
            user_agent: Client user agent
            status: "success" or "failure"
        
        Returns:
            Created AuditLog entry
        """
        log_entry = AuditLog(
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
        )
        db.add(log_entry)
        await db.commit()
        await db.refresh(log_entry)
        return log_entry
    
    @staticmethod
    async def get_logs(
        db: AsyncSession,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[AuditLog]:
        """
        Query audit logs with filters.
        
        Args:
            db: Database session
            user_id: Filter by user ID
            action: Filter by action (supports prefix matching with *)
            resource_type: Filter by resource type
            resource_id: Filter by resource ID
            start_date: Filter logs after this date
            end_date: Filter logs before this date
            skip: Pagination offset
            limit: Maximum number of results
        
        Returns:
            List of AuditLog entries
        """
        query = select(AuditLog)
        
        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        
        if action:
            if action.endswith("*"):
                # Prefix matching
                query = query.where(AuditLog.action.startswith(action[:-1]))
            else:
                query = query.where(AuditLog.action == action)
        
        if resource_type:
            query = query.where(AuditLog.resource_type == resource_type)
        
        if resource_id:
            query = query.where(AuditLog.resource_id == resource_id)
        
        if start_date:
            query = query.where(AuditLog.created_at >= start_date)
        
        if end_date:
            query = query.where(AuditLog.created_at <= end_date)
        
        query = query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)
        result = await db.execute(query)
        return result.scalars().all()
    
    @staticmethod
    async def get_user_activity(
        db: AsyncSession,
        user_id: str,
        days: int = 30,
    ) -> dict[str, Any]:
        """
        Get activity summary for a user.
        
        Args:
            db: Database session
            user_id: User ID
            days: Number of days to look back
        
        Returns:
            Activity summary with counts by action type
        """
        from datetime import timedelta
        start_date = datetime.utcnow() - timedelta(days=days)
        
        query = select(AuditLog).where(
            AuditLog.user_id == user_id,
            AuditLog.created_at >= start_date
        )
        result = await db.execute(query)
        logs = result.scalars().all()
        
        # Aggregate by action
        action_counts = {}
        for log in logs:
            action = log.action
            action_counts[action] = action_counts.get(action, 0) + 1
        
        return {
            "user_id": user_id,
            "period_days": days,
            "total_actions": len(logs),
            "action_counts": action_counts,
            "first_activity": logs[-1].created_at if logs else None,
            "last_activity": logs[0].created_at if logs else None,
        }
    
    @staticmethod
    async def get_resource_history(
        db: AsyncSession,
        resource_type: str,
        resource_id: str,
    ) -> list[AuditLog]:
        """
        Get complete audit history for a specific resource.
        
        Args:
            db: Database session
            resource_type: Type of resource
            resource_id: ID of the resource
        
        Returns:
            List of audit logs for the resource
        """
        query = select(AuditLog).where(
            AuditLog.resource_type == resource_type,
            AuditLog.resource_id == resource_id
        ).order_by(AuditLog.created_at.asc())
        
        result = await db.execute(query)
        return result.scalars().all()


# Convenience functions for common audit actions

async def log_scan_created(db: AsyncSession, user_id: str, scan_id: str, scan_type: str, ip: str = None, ua: str = None):
    """Log scan creation"""
    return await AuditService.log_action(
        db, user_id, "scan.create", "scan", scan_id,
        {"scan_type": scan_type}, ip, ua
    )

async def log_scan_stopped(db: AsyncSession, user_id: str, scan_id: str, ip: str = None, ua: str = None):
    """Log scan stop/cancellation"""
    return await AuditService.log_action(
        db, user_id, "scan.stop", "scan", scan_id,
        ip_address=ip, user_agent=ua
    )

async def log_finding_updated(db: AsyncSession, user_id: str, finding_id: str, old_status: str, new_status: str, ip: str = None, ua: str = None):
    """Log finding status change"""
    return await AuditService.log_action(
        db, user_id, "finding.update", "finding", finding_id,
        {"old_status": old_status, "new_status": new_status}, ip, ua
    )

async def log_target_created(db: AsyncSession, user_id: str, target_id: str, domain: str, ip: str = None, ua: str = None):
    """Log target creation"""
    return await AuditService.log_action(
        db, user_id, "target.create", "target", target_id,
        {"domain": domain}, ip, ua
    )

async def log_auth_login(db: AsyncSession, user_id: str, method: str = "password", ip: str = None, ua: str = None, status: str = "success"):
    """Log authentication attempt"""
    return await AuditService.log_action(
        db, user_id, "auth.login", "user", user_id,
        {"method": method}, ip, ua, status
    )

async def log_approval_requested(db: AsyncSession, user_id: str, approval_id: str, request_type: str, ip: str = None, ua: str = None):
    """Log approval request"""
    return await AuditService.log_action(
        db, user_id, "approval.request", "approval", approval_id,
        {"request_type": request_type}, ip, ua
    )

async def log_approval_reviewed(db: AsyncSession, reviewer_id: str, approval_id: str, decision: str, ip: str = None, ua: str = None):
    """Log approval review"""
    return await AuditService.log_action(
        db, reviewer_id, "approval.review", "approval", approval_id,
        {"decision": decision}, ip, ua
    )

async def log_dangerous_action_blocked(db: AsyncSession, user_id: str, action: str, reason: str, ip: str = None, ua: str = None):
    """Log blocked dangerous action"""
    return await AuditService.log_action(
        db, user_id, "security.blocked", "system", None,
        {"action": action, "reason": reason}, ip, ua, "blocked"
    )
