"""
Public API endpoints - No authentication required
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.schemas import FindingResponse, FindingStats, FindingUpdate
from app.models import Finding, Scan
from app.database import get_db

router = APIRouter(prefix="/public", tags=["public"])


@router.get("/findings")
async def list_findings(
    skip: int = 0,
    limit: int = 100,
    scan_id: UUID = None,
    severity: str = None,
    scanner: str = None,
    db: AsyncSession = Depends(get_db)
):
    """List all findings without authentication"""
    query = select(Finding)

    if scan_id:
        query = query.where(Finding.scan_id == str(scan_id))
    if severity:
        query = query.where(Finding.severity == severity)
    if scanner:
        query = query.where(Finding.scanner == scanner)

    query = query.offset(skip).limit(limit).order_by(Finding.created_at.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/findings/stats", response_model=FindingStats)
async def get_finding_stats(
    db: AsyncSession = Depends(get_db)
):
    """Get finding statistics without authentication"""
    query = select(Finding)
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


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific finding without authentication"""
    result = await db.execute(
        select(Finding)
        .where(Finding.id == str(finding_id))
    )
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )

    return finding


@router.get("/scans")
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status: str = None,
    db: AsyncSession = Depends(get_db)
):
    """List all scans without authentication"""
    query = select(Scan)

    if status:
        query = query.where(Scan.status == status)

    query = query.offset(skip).limit(limit).order_by(Scan.created_at.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db)
):
    """Get a specific scan without authentication"""
    result = await db.execute(
        select(Scan)
        .where(Scan.id == str(scan_id))
    )
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    return scan