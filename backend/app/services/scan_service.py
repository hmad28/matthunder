"""
Scan Service - Business logic for scan operations
"""
from uuid import UUID
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import Scan, ScanLog, Target
from app.schemas import ScanCreate
from app.core.exceptions import NotFoundException, ForbiddenException
from app.core.logging import get_logger

logger = get_logger(__name__)


class ScanService:
    """Service for scan operations"""
    
    @staticmethod
    async def create_scan(
        scan_data: ScanCreate,
        user_id: UUID,
        db: AsyncSession
    ) -> Scan:
        """Create a new scan"""
        # Verify target exists and belongs to user
        result = await db.execute(
            select(Target).where(Target.id == str(scan_data.target_id))
        )
        target = result.scalar_one_or_none()
        
        if not target:
            raise NotFoundException("Target not found")
        
        if target.created_by != user_id:
            raise ForbiddenException("Not authorized to scan this target")
        
        # Create scan record
        scan = Scan(
            target_id=str(scan_data.target_id),
            scan_type=scan_data.scan_type,
            speed=scan_data.speed,
            metadata_=scan_data.metadata,
            created_by=user_id,
            status="pending"
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        logger.info("scan_created", scan_id=str(scan.id), type=scan.scan_type)
        
        return scan
    
    @staticmethod
    async def get_scan(scan_id: UUID, user_id: UUID, db: AsyncSession) -> Scan:
        """Get scan by ID"""
        result = await db.execute(select(Scan).where(Scan.id == str(scan_id)))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise NotFoundException("Scan not found")
        
        if scan.created_by != user_id:
            raise ForbiddenException("Not authorized to access this scan")
        
        return scan
    
    @staticmethod
    async def add_log(
        scan_id: UUID,
        level: str,
        message: str,
        db: AsyncSession
    ) -> ScanLog:
        """Add a log entry to a scan"""
        log = ScanLog(
            scan_id=scan_id,
            level=level,
            message=message
        )
        db.add(log)
        await db.commit()
        
        # Publish to Redis for WebSocket streaming
        try:
            from redis import asyncio as aioredis
            from app.config import settings
            if not settings.REDIS_URL:
                return log
            redis = aioredis.from_url(settings.REDIS_URL)
            await redis.publish(
                f"scan:{scan_id}:logs",
                f"{level}|{message}"
            )
            await redis.close()
        except Exception as e:
            logger.error("redis_publish_failed", error=str(e))
        
        return log
    
    @staticmethod
    async def update_status(
        scan_id: UUID,
        status: str,
        db: AsyncSession
    ) -> Scan:
        """Update scan status"""
        result = await db.execute(select(Scan).where(Scan.id == str(scan_id)))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise NotFoundException("Scan not found")
        
        scan.status = status
        
        if status == "running":
            scan.started_at = datetime.utcnow()
        elif status in ["completed", "failed", "cancelled"]:
            scan.completed_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(scan)
        
        logger.info("scan_status_updated", scan_id=str(scan_id), status=status)
        
        return scan
    
    @staticmethod
    async def execute_scan(scan_id: str):
        """Execute scan in local background mode without Celery."""
        from app.database import async_session
        from app.hunting.runner import NormalHuntingRunner
        from sqlalchemy import select
        
        async with async_session() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            
            if not scan:
                return
            
            try:
                scan.status = "running"
                scan.started_at = datetime.utcnow()
                await db.commit()

                result = await db.execute(select(Target).where(Target.id == scan.target_id))
                target = result.scalar_one_or_none()
                if not target:
                    raise NotFoundException("Target not found")

                await NormalHuntingRunner().run(scan, target, db)

                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
                
                logger.info("scan_completed", scan_id=str(scan.id))
                
            except Exception as e:
                logger.error("scan_failed", scan_id=str(scan.id), error=str(e))
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
