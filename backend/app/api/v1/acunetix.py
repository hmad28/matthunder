"""
Acunetix Integration API routes
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import get_db
from app.core.security import get_current_user
from app.models import User
from app.config import settings
from app.services.acunetix_service import AcunetixService

router = APIRouter(prefix="/acunetix", tags=["acunetix"])


@router.get("/status")
async def get_status(
    current_user: User = Depends(get_current_user)
):
    """Get Acunetix connection status"""
    if not settings.ACUNETIX_URL or not settings.ACUNETIX_API_KEY:
        return {
            "configured": False,
            "message": "Acunetix not configured. Set ACUNETIX_URL and ACUNETIX_API_KEY in environment."
        }
    
    try:
        status = await AcunetixService.check_connection()
        return {
            "configured": True,
            "connected": status["connected"],
            "version": status.get("version"),
            "message": status.get("message")
        }
    except Exception as e:
        return {
            "configured": True,
            "connected": False,
            "message": f"Connection failed: {str(e)}"
        }


@router.get("/targets")
async def get_targets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get targets from Acunetix"""
    if not settings.ACUNETIX_URL or not settings.ACUNETIX_API_KEY:
        raise HTTPException(status_code=400, detail="Acunetix not configured")
    
    return await AcunetixService.get_targets()


@router.get("/scans")
async def get_scans(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scans from Acunetix"""
    if not settings.ACUNETIX_URL or not settings.ACUNETIX_API_KEY:
        raise HTTPException(status_code=400, detail="Acunetix not configured")
    
    return await AcunetixService.get_scans(limit=limit)


@router.get("/vulns")
async def get_vulnerabilities(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get vulnerabilities from Acunetix"""
    if not settings.ACUNETIX_URL or not settings.ACUNETIX_API_KEY:
        raise HTTPException(status_code=400, detail="Acunetix not configured")
    
    return await AcunetixService.get_vulnerabilities(limit=limit)


@router.get("/vulns/{scan_id}")
async def get_scan_vulnerabilities(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get vulnerabilities for a specific Acunetix scan"""
    if not settings.ACUNETIX_URL or not settings.ACUNETIX_API_KEY:
        raise HTTPException(status_code=400, detail="Acunetix not configured")
    
    return await AcunetixService.get_scan_vulnerabilities(scan_id)
