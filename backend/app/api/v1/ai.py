"""
AI Analysis API routes
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas import AIProviderInfo, AIAnalyzeRequest, AIAnalyzeResponse, AIHuntRequest
from app.database import get_db
from app.core.security import get_current_user
from app.models import User
from app.services.ai_service import AIService

router = APIRouter(prefix="/ai", tags=["ai"])


@router.get("/providers", response_model=list[AIProviderInfo])
async def list_providers(
    current_user: User = Depends(get_current_user)
):
    """List available AI providers"""
    return AIService.get_available_providers()


@router.post("/analyze", response_model=AIAnalyzeResponse)
async def analyze(
    request: AIAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run AI analysis on a prompt"""
    return await AIService.analyze(
        prompt=request.prompt,
        provider=request.provider,
        model=request.model,
        scan_id=request.scan_id,
        user_id=current_user.id,
        db=db
    )


@router.post("/hunt")
async def ai_hunt(
    request: AIHuntRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Run AI-powered vulnerability hunting"""
    return await AIService.hunt(
        target_id=request.target_id,
        provider=request.provider,
        model=request.model,
        focus=request.focus,
        user_id=current_user.id,
        db=db
    )
