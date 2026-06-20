"""
Findings API routes
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.schemas import FindingResponse, FindingUpdate, FindingStats
from app.models import Finding, Scan, User
from app.database import get_db
from app.core.security import get_current_user
from app.core.exceptions import NotFoundException, ForbiddenException

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/", response_model=list[FindingResponse])
async def list_findings(
    skip: int = 0,
    limit: int = 100,
    scan_id: UUID = None,
    severity: str = None,
    scanner: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List findings with optional filters"""
    query = select(Finding).join(Scan).where(Scan.created_by == current_user.id)
    
    if scan_id:
        query = query.where(Finding.scan_id == str(scan_id))
    if severity:
        query = query.where(Finding.severity == severity)
    if scanner:
        query = query.where(Finding.scanner == scanner)
    
    query = query.offset(skip).limit(limit).order_by(Finding.created_at.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/stats", response_model=FindingStats)
async def get_finding_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get finding statistics"""
    query = select(Finding).join(Scan).where(Scan.created_by == current_user.id)
    result = await db.execute(query)
    findings = result.scalars().all()
    
    stats = FindingStats(
        total=len(findings),
        critical=sum(1 for f in findings if f.severity == "critical"),
        high=sum(1 for f in findings if f.severity == "high"),
        medium=sum(1 for f in findings if f.severity == "medium"),
        low=sum(1 for f in findings if f.severity == "low"),
        info=sum(1 for f in findings if f.severity == "info")
    )
    
    return stats


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific finding"""
    result = await db.execute(
        select(Finding)
        .join(Scan)
        .where(Finding.id == str(finding_id), Scan.created_by == current_user.id)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise NotFoundException("Finding not found")
    
    return finding


@router.put("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: UUID,
    finding_data: FindingUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a finding"""
    result = await db.execute(
        select(Finding)
        .join(Scan)
        .where(Finding.id == str(finding_id), Scan.created_by == current_user.id)
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise NotFoundException("Finding not found")
    
    if finding_data.status is not None:
        finding.status = finding_data.status
    if finding_data.severity is not None:
        finding.severity = finding_data.severity
    
    await db.commit()
    await db.refresh(finding)
    return finding
