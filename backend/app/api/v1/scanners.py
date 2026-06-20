"""
Scanners API routes
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import ScannerInfo, ScannerRunRequest, ScannerRunResponse
from app.database import get_db
from app.core.security import get_current_user
from app.models import User
from app.services.scanner_service import ScannerService

router = APIRouter(prefix="/scanners", tags=["scanners"])


@router.get("/", response_model=list[ScannerInfo])
async def list_scanners(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all available scanners"""
    return await ScannerService.get_available_scanners()


@router.post("/{scanner_name}/run", response_model=ScannerRunResponse)
async def run_scanner(
    scanner_name: str,
    request: ScannerRunRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run a specific scanner"""
    return await ScannerService.run_scanner(
        scanner_name=scanner_name,
        target=request.target,
        config=request.config,
        user_id=current_user.id,
        db=db
    )
