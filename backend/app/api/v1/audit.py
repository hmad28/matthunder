"""
Audit log API routes
"""
from datetime import datetime
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import AuditLogResponse
from app.models import User
from app.database import get_db
from app.core.security import get_current_user, get_current_superuser
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/", response_model=list[AuditLogResponse])
async def list_audit_logs(
    user_id: str = None,
    action: str = None,
    resource_type: str = None,
    resource_id: str = None,
    start_date: datetime = None,
    end_date: datetime = None,
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser)
):
    """
    List audit logs (superuser only).
    
    Regular users can only view their own activity via /audit/me endpoint.
    """
    logs = await AuditService.get_logs(
        db, user_id, action, resource_type, resource_id,
        start_date, end_date, skip, limit
    )
    return logs


@router.get("/me", response_model=list[AuditLogResponse])
async def get_my_audit_logs(
    action: str = None,
    resource_type: str = None,
    resource_id: str = None,
    start_date: datetime = None,
    end_date: datetime = None,
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get audit logs for current user"""
    logs = await AuditService.get_logs(
        db, current_user.id, action, resource_type, resource_id,
        start_date, end_date, skip, limit
    )
    return logs


@router.get("/me/activity")
async def get_my_activity(
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get activity summary for current user"""
    activity = await AuditService.get_user_activity(db, current_user.id, days)
    return activity


@router.get("/resource/{resource_type}/{resource_id}", response_model=list[AuditLogResponse])
async def get_resource_history(
    resource_type: str,
    resource_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser)
):
    """Get complete audit history for a specific resource (superuser only)"""
    logs = await AuditService.get_resource_history(db, resource_type, resource_id)
    return logs


@router.get("/users/{user_id}/activity")
async def get_user_activity(
    user_id: str,
    days: int = Query(default=30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_superuser)
):
    """Get activity summary for a specific user (superuser only)"""
    activity = await AuditService.get_user_activity(db, user_id, days)
    return activity
