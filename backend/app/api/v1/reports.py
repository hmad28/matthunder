"""
Reports API routes
"""
from uuid import UUID
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.schemas import ReportResponse
from app.models import Report, Scan, User
from app.database import get_db
from app.core.security import get_current_user
from app.core.exceptions import NotFoundException, ForbiddenException
import os

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/", response_model=list[ReportResponse])
async def list_reports(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all reports for current user"""
    result = await db.execute(
        select(Report)
        .join(Scan)
        .where(Scan.created_by == current_user.id)
        .offset(skip)
        .limit(limit)
        .order_by(Report.generated_at.desc())
    )
    return result.scalars().all()


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific report"""
    result = await db.execute(
        select(Report)
        .join(Scan)
        .where(Report.id == str(report_id), Scan.created_by == current_user.id)
    )
    report = result.scalar_one_or_none()
    
    if not report:
        raise NotFoundException("Report not found")
    
    return report


@router.get("/{report_id}/download")
async def download_report(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Download a report file"""
    result = await db.execute(
        select(Report)
        .join(Scan)
        .where(Report.id == str(report_id), Scan.created_by == current_user.id)
    )
    report = result.scalar_one_or_none()
    
    if not report:
        raise NotFoundException("Report not found")
    
    if not report.file_path or not os.path.exists(report.file_path):
        raise NotFoundException("Report file not found")
    
    return FileResponse(
        path=report.file_path,
        filename=f"report-{report.id}.{report.report_type}",
        media_type="application/octet-stream"
    )
