"""
Pipeline Service - Business logic for pipeline operations
"""
from uuid import UUID
from datetime import datetime
import asyncio
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import Scan, Target
from app.schemas import PipelineStatus
from app.core.exceptions import NotFoundException, ForbiddenException
from app.core.logging import get_logger
from app.tasks.dispatch import celery_enabled

logger = get_logger(__name__)


class PipelineService:
    """Service for pipeline operations"""
    
    # Pipeline phases
    PHASES = [
        {
            "name": "scope-intake",
            "description": "Scope normalization and authorization guardrail",
            "scanners": []
        },
        {
            "name": "asset-discovery",
            "description": "Asset discovery and candidate mapping",
            "scanners": ["subdomain", "takeover"]
        },
        {
            "name": "live-host-probing",
            "description": "Live host probing and WAF detection",
            "scanners": ["httpx", "waf"]
        },
        {
            "name": "service-discovery",
            "description": "Port and technology discovery",
            "scanners": ["portscan", "tech"]
        },
        {
            "name": "deep-entry-mapping",
            "description": "Endpoint, JavaScript, API, and parameter mapping",
            "scanners": ["crawler", "jsanalysis", "apirecon", "fuzzer"]
        },
        {
            "name": "safe-validation",
            "description": "Evidence-driven vulnerability validation",
            "scanners": ["xss", "sqli", "lfi", "openredirect", "cors", "ssrf", "hostheader", "ssti", "crlf", "graphql"]
        }
    ]
    
    @staticmethod
    async def run_pipeline(
        target_id: UUID,
        speed: str,
        phases: Optional[list[str]],
        user_id: UUID,
        db: AsyncSession
    ) -> PipelineStatus:
        """Run the full scanning pipeline"""
        # Verify target exists and belongs to user
        result = await db.execute(select(Target).where(Target.id == str(target_id)))
        target = result.scalar_one_or_none()
        
        if not target:
            raise NotFoundException("Target not found")
        
        if target.created_by != user_id:
            raise ForbiddenException("Not authorized to scan this target")
        
        # Create pipeline scan
        scan = Scan(
            target_id=str(target_id),
            scan_type="pipeline",
            speed=speed,
            metadata_={"phases": phases or [p["name"] for p in PipelineService.PHASES]},
            created_by=user_id,
            status="running",
            started_at=datetime.utcnow()
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Queue pipeline task. Local-native mode runs without Redis/Celery.
        if celery_enabled():
            from app.tasks.pipeline_tasks import run_pipeline_task
            task = run_pipeline_task.delay(str(scan.id), phases)
            scan.celery_task_id = task.id
        else:
            from app.services.scan_service import ScanService
            asyncio.create_task(ScanService.execute_scan(str(scan.id)))
            scan.celery_task_id = None
        await db.commit()
        
        logger.info("pipeline_started", scan_id=str(scan.id), target=target.domain)
        
        return PipelineStatus(
            scan_id=scan.id,
            current_phase="scope-intake",
            completed_phases=[],
            status="running",
            progress=0.0
        )
    
    @staticmethod
    async def get_pipeline_status(
        scan_id: UUID,
        user_id: UUID,
        db: AsyncSession
    ) -> PipelineStatus:
        """Get pipeline execution status"""
        result = await db.execute(select(Scan).where(Scan.id == str(scan_id)))
        scan = result.scalar_one_or_none()
        
        if not scan:
            raise NotFoundException("Scan not found")
        
        if scan.created_by != user_id:
            raise ForbiddenException("Not authorized to access this scan")
        
        if scan.scan_type != "pipeline":
            raise ForbiddenException("Scan is not a pipeline")
        
        metadata = scan.metadata_ or {}
        completed_phases = metadata.get("completed_phases", [])
        current_phase = metadata.get("current_phase", "unknown")
        
        total_phases = len(PipelineService.PHASES)
        progress = len(completed_phases) / total_phases if total_phases > 0 else 0.0
        
        return PipelineStatus(
            scan_id=scan.id,
            current_phase=current_phase,
            completed_phases=completed_phases,
            status=scan.status,
            progress=progress
        )
