"""
Pipeline tasks - Celery tasks for pipeline execution
"""
from datetime import datetime
from app.tasks.celery_app import celery
from app.core.logging import get_logger

logger = get_logger(__name__)


@celery.task(bind=True, name="run_pipeline_task")
def run_pipeline_task(self, scan_id: str, phases: list[str] = None):
    """Execute pipeline phases"""
    import asyncio
    
    async def _execute():
        from app.database import async_session
        from app.hunting.runner import NormalHuntingRunner
        from app.models import Scan, Target
        from sqlalchemy import select
        
        async with async_session() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            
            if not scan:
                return
            
            try:
                # Update metadata
                metadata = scan.metadata_ or {}
                metadata["phases"] = phases or [
                    "scope-intake",
                    "asset-discovery",
                    "live-host-probing",
                    "service-discovery",
                    "deep-entry-mapping",
                    "attack-surface-ranking",
                    "safe-validation",
                    "dedupe-and-report",
                ]
                metadata["completed_phases"] = []
                scan.metadata_ = metadata
                await db.commit()

                result = await db.execute(select(Target).where(Target.id == scan.target_id))
                target = result.scalar_one_or_none()
                if not target:
                    raise RuntimeError("Target not found")

                logger.info("executing_normal_hunting_pipeline", scan_id=scan_id, target=target.domain)
                await NormalHuntingRunner().run(scan, target, db)
                
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
                
                logger.info("pipeline_completed", scan_id=scan_id)
                
            except Exception as e:
                logger.error("pipeline_failed", scan_id=scan_id, error=str(e))
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
    
    asyncio.run(_execute())


async def _execute_phase(scan, phase: str, db):
    """Execute a single pipeline phase"""
    # In production: import and execute actual scanners for each phase
    # This is where you'd call the actual scanner functions
    
    phase_scanners = {
        "passive_recon": ["subfinder", "assetfinder"],
        "active_recon": ["httpx", "portscan", "waf", "tech"],
        "content_discovery": ["gau", "katana", "jsanalysis", "fuzzer", "apirecon"],
        "automated_scanning": ["nuclei"],
        "vulnerability_scan": ["sqli", "xss", "lfi", "cors", "ssti", "ssrf", "hostheader"],
        "intel_discovery": ["blh", "tpa", "cred", "graphql", "jsanalysis"]
    }
    
    scanners = phase_scanners.get(phase, [])
    logger.info("phase_scanners", phase=phase, scanners=scanners)
    
    # In production: execute each scanner
    # for scanner_name in scanners:
    #     from scanners import SCANNER_REGISTRY
    #     scanner_func = SCANNER_REGISTRY.get(scanner_name)
    #     if scanner_func:
    #         await asyncio.to_thread(scanner_func, target)
