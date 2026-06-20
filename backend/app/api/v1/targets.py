"""
Targets API routes
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from app.schemas import TargetCreate, TargetUpdate, TargetResponse
from app.models import Target, User
from app.database import get_db
from app.hunting.engine import TargetInput
from app.core.security import get_current_user
from app.core.exceptions import BadRequestException, NotFoundException, ForbiddenException

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("/", response_model=list[TargetResponse])
async def list_targets(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all targets for current user"""
    result = await db.execute(
        select(Target)
        .where(Target.created_by == current_user.id)
        .offset(skip)
        .limit(limit)
        .order_by(Target.created_at.desc())
    )
    return result.scalars().all()


@router.post("/", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(
    target_data: TargetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create a new target"""
    try:
        normalized = TargetInput.normalize(target_data.domain, target_data.scope)
    except ValueError as exc:
        raise BadRequestException(str(exc))

    target = Target(
        domain=normalized.domain,
        notes=target_data.notes,
        scope=normalized.scope,
        created_by=current_user.id
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific target"""
    result = await db.execute(select(Target).where(Target.id == str(target_id)))
    target = result.scalar_one_or_none()
    
    if not target:
        raise NotFoundException("Target not found")
    
    if target.created_by != current_user.id:
        raise ForbiddenException("Not authorized to access this target")
    
    return target


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: UUID,
    target_data: TargetUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update a target"""
    result = await db.execute(select(Target).where(Target.id == str(target_id)))
    target = result.scalar_one_or_none()
    
    if not target:
        raise NotFoundException("Target not found")
    
    if target.created_by != current_user.id:
        raise ForbiddenException("Not authorized to update this target")
    
    # Update fields
    if target_data.domain is not None:
        try:
            normalized = TargetInput.normalize(target_data.domain, target_data.scope or target.scope)
        except ValueError as exc:
            raise BadRequestException(str(exc))
        target.domain = normalized.domain
        target.scope = normalized.scope
    if target_data.notes is not None:
        target.notes = target_data.notes
    if target_data.scope is not None:
        try:
            normalized = TargetInput.normalize(target.domain, target_data.scope)
        except ValueError as exc:
            raise BadRequestException(str(exc))
        target.scope = normalized.scope
    
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(
    target_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a target"""
    result = await db.execute(select(Target).where(Target.id == str(target_id)))
    target = result.scalar_one_or_none()
    
    if not target:
        raise NotFoundException("Target not found")
    
    if target.created_by != current_user.id:
        raise ForbiddenException("Not authorized to delete this target")
    
    await db.delete(target)
    await db.commit()
    return None
