"""
Approval workflow API routes
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import ApprovalRequestCreate, ApprovalRequestResponse, ApprovalReview
from app.models import User
from app.database import get_db
from app.core.security import get_current_user
from app.services.approval_service import ApprovalService

router = APIRouter(prefix="/approvals", tags=["approvals"])


@router.post("/", response_model=ApprovalRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_approval_request(
    request_data: ApprovalRequestCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new approval request"""
    from datetime import datetime, timedelta
    
    expires_at = datetime.utcnow() + timedelta(minutes=request_data.expires_in_minutes)
    
    request = ApprovalRequest(
        request_type=request_data.request_type,
        requestor_id=current_user.id,
        target_id=str(request_data.target_id) if request_data.target_id else None,
        scan_id=str(request_data.scan_id) if request_data.scan_id else None,
        payload=request_data.payload,
        reason=request_data.reason,
        status="pending",
        expires_at=expires_at,
    )
    
    db.add(request)
    await db.commit()
    await db.refresh(request)
    
    return request


@router.get("/", response_model=list[ApprovalRequestResponse])
async def list_approval_requests(
    status_filter: str = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List approval requests (pending for reviewers, all for requestors)"""
    if status_filter == "pending":
        # Show pending requests that need review (not created by current user)
        requests = await ApprovalService.list_pending_requests(db, current_user.id, skip, limit)
    else:
        # Show all requests created by current user
        requests = await ApprovalService.get_user_requests(db, current_user.id, status_filter, skip, limit)
    
    return requests


@router.get("/{request_id}", response_model=ApprovalRequestResponse)
async def get_approval_request(
    request_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific approval request"""
    request = await ApprovalService.get_request(db, str(request_id))
    
    if not request:
        raise HTTPException(status_code=404, detail="Approval request not found")
    
    # Only requestor or reviewer can view
    if request.requestor_id != current_user.id and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Not authorized to view this request")
    
    return request


@router.post("/{request_id}/review", response_model=ApprovalRequestResponse)
async def review_approval_request(
    request_id: UUID,
    review_data: ApprovalReview,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Review an approval request (approve or reject)"""
    try:
        request = await ApprovalService.review_request(
            db, str(request_id), current_user.id, review_data.status, review_data.comment
        )
        return request
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{request_id}/cancel", response_model=ApprovalRequestResponse)
async def cancel_approval_request(
    request_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Cancel an approval request (by requestor)"""
    try:
        request = await ApprovalService.cancel_request(db, str(request_id), current_user.id)
        return request
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/stats/summary")
async def get_approval_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get approval statistics for current user"""
    from sqlalchemy import select, func
    from app.models import ApprovalRequest
    
    # Count by status
    query = select(
        ApprovalRequest.status,
        func.count(ApprovalRequest.id)
    ).where(
        ApprovalRequest.requestor_id == current_user.id
    ).group_by(ApprovalRequest.status)
    
    result = await db.execute(query)
    stats = {status: count for status, count in result.all()}
    
    # Count pending reviews needed (for superusers)
    if current_user.is_superuser:
        pending_review = await db.execute(
            select(func.count(ApprovalRequest.id)).where(
                ApprovalRequest.status == "pending",
                ApprovalRequest.requestor_id != current_user.id
            )
        )
        stats["pending_review"] = pending_review.scalar() or 0
    
    return stats
