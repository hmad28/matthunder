"""
Scans API routes
"""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.schemas import ScanCreate, ScanResponse, ScanStatus, ScanLogResponse
from app.models import Scan, ScanLog, Target, User
from app.database import get_db
from app.core.security import get_current_user
from app.core.exceptions import NotFoundException, ForbiddenException, BadRequestException
from app.services.scan_service import ScanService
from app.tasks.dispatch import celery_enabled

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/", response_model=list[ScanResponse])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    status_filter: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all scans for current user"""
    query = select(Scan).where(Scan.created_by == current_user.id)
    
    if status_filter:
        query = query.where(Scan.status == status_filter)
    
    query = query.offset(skip).limit(limit).order_by(Scan.created_at.desc())
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create and start a new scan"""
    # Verify target exists and belongs to user
    result = await db.execute(select(Target).where(Target.id == str(scan_data.target_id)))
    target = result.scalar_one_or_none()
    
    if not target:
        raise NotFoundException("Target not found")
    
    if target.created_by != current_user.id:
        raise ForbiddenException("Not authorized to scan this target")
    
    # Create scan
    scan = Scan(
        target_id=str(scan_data.target_id),
        scan_type=scan_data.scan_type,
        speed=scan_data.speed,
        metadata_=scan_data.metadata,
        created_by=current_user.id,
        status="pending"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Start scan in background. Local-native mode does not require Redis/Celery.
    if celery_enabled():
        from app.tasks.scan_tasks import run_scan_task
        task = run_scan_task.delay(str(scan.id))
        scan.celery_task_id = task.id
    else:
        background_tasks.add_task(ScanService.execute_scan, str(scan.id))
        scan.celery_task_id = None
    scan.status = "running"
    await db.commit()
    await db.refresh(scan)
    
    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific scan"""
    result = await db.execute(select(Scan).where(Scan.id == str(scan_id)))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise NotFoundException("Scan not found")
    
    if scan.created_by != current_user.id:
        raise ForbiddenException("Not authorized to access this scan")
    
    return scan


@router.get("/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan status"""
    result = await db.execute(select(Scan).where(Scan.id == str(scan_id)))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise NotFoundException("Scan not found")
    
    if scan.created_by != current_user.id:
        raise ForbiddenException("Not authorized to access this scan")
    
    return scan


@router.post("/{scan_id}/stop", response_model=ScanResponse)
async def stop_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop a running scan"""
    result = await db.execute(select(Scan).where(Scan.id == str(scan_id)))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise NotFoundException("Scan not found")
    
    if scan.created_by != current_user.id:
        raise ForbiddenException("Not authorized to stop this scan")
    
    if scan.status != "running":
        raise BadRequestException("Scan is not running")
    
    # Revoke Celery task
    if scan.celery_task_id:
        from app.tasks.celery_app import celery
        celery.control.revoke(scan.celery_task_id, terminate=True)
    
    scan.status = "cancelled"
    await db.commit()
    await db.refresh(scan)
    
    return scan


@router.get("/{scan_id}/logs", response_model=list[ScanLogResponse])
async def get_scan_logs(
    scan_id: UUID,
    limit: int = 1000,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scan logs"""
    # Verify scan exists and belongs to user
    result = await db.execute(select(Scan).where(Scan.id == str(scan_id)))
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise NotFoundException("Scan not found")
    
    if scan.created_by != current_user.id:
        raise ForbiddenException("Not authorized to access this scan")
    
    # Get logs
    result = await db.execute(
        select(ScanLog)
        .where(ScanLog.scan_id == str(scan_id))
        .order_by(ScanLog.timestamp.asc())
        .limit(limit)
    )
    return result.scalars().all()


@router.websocket("/{scan_id}/ws")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: UUID
):
    """WebSocket endpoint for real-time scan logs"""
    await websocket.accept()
    
    try:
        # TODO: Implement proper authentication for WebSocket
        # For now, just stream logs
        
        from app.database import async_session
        from redis import asyncio as aioredis
        from app.config import settings
        
        redis = aioredis.from_url(settings.REDIS_URL)
        pubsub = redis.pubsub()
        channel = f"scan:{scan_id}:logs"
        await pubsub.subscribe(channel)
        
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    await websocket.send_json(message["data"])
        finally:
            await pubsub.unsubscribe(channel)
            await redis.close()
            
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await websocket.close(code=1011, reason=str(e))
