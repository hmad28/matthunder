"""
Pipeline API routes
"""
from uuid import UUID
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import PipelineRunRequest, PipelineStatus
from app.database import get_db
from app.core.security import get_current_user
from app.models import User
from app.services.pipeline_service import PipelineService

router = APIRouter(prefix="/pipeline", tags=["pipeline"])


@router.post("/run", response_model=PipelineStatus)
async def run_pipeline(
    request: PipelineRunRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run the full scanning pipeline"""
    return await PipelineService.run_pipeline(
        target_id=request.target_id,
        speed=request.speed,
        phases=request.phases,
        user_id=current_user.id,
        db=db
    )


@router.get("/{scan_id}/status", response_model=PipelineStatus)
async def get_pipeline_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get pipeline execution status"""
    return await PipelineService.get_pipeline_status(scan_id, current_user.id, db)
