"""
Scan tasks - Celery tasks for scan execution
"""
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from app.tasks.celery_app import celery
from app.core.logging import get_logger

logger = get_logger(__name__)


@celery.task(bind=True, name="run_scan_task")
def run_scan_task(self, scan_id: str):
    """Execute a scan in background"""
    from app.database import async_session
    from app.models import Scan
    from sqlalchemy import select
    import asyncio
    
    async def _execute():
        async with async_session() as db:
            # Get scan
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            
            if not scan:
                logger.error("scan_not_found", scan_id=scan_id)
                return
            
            try:
                # Update status to running
                scan.status = "running"
                scan.started_at = datetime.utcnow()
                await db.commit()
                
                # Execute scan based on type
                if scan.scan_type in ["light", "dark", "deep"]:
                    await _run_recon_scan(scan, db)
                elif scan.scan_type == "pipeline":
                    await _run_pipeline_scan(scan, db)
                else:
                    await _run_inline_scan(scan, db)
                
                # Mark as completed
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
                
                logger.info("scan_completed", scan_id=scan_id)
                
            except Exception as e:
                logger.error("scan_failed", scan_id=scan_id, error=str(e))
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
    
    asyncio.run(_execute())


async def _run_recon_scan(scan, db):
    """Run light/dark/deep recon scan"""
    from app.models import Target
    from sqlalchemy import select
    from app.hunting.runner import NormalHuntingRunner
    
    # Get target
    result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = result.scalar_one_or_none()
    
    if not target:
        raise Exception("Target not found")
    
    logger.info("running_recon_scan", target=target.domain, type=scan.scan_type)
    await NormalHuntingRunner().run(scan, target, db)


async def _run_pipeline_scan(scan, db):
    """Run full pipeline scan"""
    from app.models import Target
    from sqlalchemy import select
    from app.hunting.runner import NormalHuntingRunner
    
    result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = result.scalar_one_or_none()
    
    if not target:
        raise Exception("Target not found")
    
    logger.info("running_pipeline_scan", target=target.domain)
    await NormalHuntingRunner().run(scan, target, db)


async def _run_inline_scan(scan, db):
    """Run inline scanner (blh, tpa, cred, etc.)"""
    import asyncio

    scanner_name = scan.scan_type
    config = scan.metadata_ or {}
    target = config.get("target")
    from app.hunting.engine import FindingNormalizer, LegacyResultLoader, ScannerAdapterRegistry
    from app.models import Finding
    
    if not target:
        raise Exception("Target not specified in scan metadata")
    
    logger.info("running_inline_scanner", scanner=scanner_name, target=target)
    result = await asyncio.to_thread(ScannerAdapterRegistry().run, scanner_name, target)
    raw_findings = []
    if isinstance(result.get("findings"), list):
        raw_findings = [
            {**item, "scanner": item.get("scanner", scanner_name)}
            for item in result["findings"]
            if isinstance(item, dict)
        ]
    elif result.get("evidence") and (result.get("url") or result.get("target_url")):
        raw_findings = [{**result, "scanner": scanner_name}]
    raw_findings.extend(LegacyResultLoader().load(result.get("scan_id"), scanner_name))

    normalized_findings = FindingNormalizer().normalize(raw_findings)
    for item in normalized_findings:
        db.add(
            Finding(
                scan_id=scan.id,
                scanner=item["scanner"],
                severity=item["severity"],
                category=item["category"],
                title=item["title"],
                description=item["description"],
                url=item["url"],
                source_url=item.get("source_url"),
                evidence=item["evidence"],
                http_code=item.get("http_code"),
                status=item["status"],
                remediation=item.get("remediation"),
                metadata_=item["metadata"],
            )
        )
    scan.metadata_ = {
        **(scan.metadata_ or {}),
        "adapter_result": result,
        "normalized_findings": len(normalized_findings),
    }
    await db.commit()


@celery.task(bind=True, name="run_scanner_task")
def run_scanner_task(self, scan_id: str, scanner_name: str, target: str, config: dict):
    """Execute a specific scanner"""
    import asyncio
    
    async def _execute():
        from app.database import async_session
        from app.models import Scan
        from sqlalchemy import select
        
        async with async_session() as db:
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            
            if not scan:
                return
            
            try:
                scan.status = "running"
                await db.commit()
                
                logger.info("executing_scanner", scanner=scanner_name, target=target)
                from app.hunting.engine import FindingNormalizer, LegacyResultLoader, ScannerAdapterRegistry
                from app.models import Finding

                result = await asyncio.to_thread(ScannerAdapterRegistry().run, scanner_name, target)
                raw_findings = []
                if isinstance(result.get("findings"), list):
                    raw_findings = [
                        {**item, "scanner": item.get("scanner", scanner_name)}
                        for item in result["findings"]
                        if isinstance(item, dict)
                    ]
                elif result.get("evidence") and (result.get("url") or result.get("target_url")):
                    raw_findings = [{**result, "scanner": scanner_name}]
                raw_findings.extend(LegacyResultLoader().load(result.get("scan_id"), scanner_name))

                normalized_findings = FindingNormalizer().normalize(raw_findings)
                for item in normalized_findings:
                    db.add(
                        Finding(
                            scan_id=scan.id,
                            scanner=item["scanner"],
                            severity=item["severity"],
                            category=item["category"],
                            title=item["title"],
                            description=item["description"],
                            url=item["url"],
                            source_url=item.get("source_url"),
                            evidence=item["evidence"],
                            http_code=item.get("http_code"),
                            status=item["status"],
                            remediation=item.get("remediation"),
                            metadata_=item["metadata"],
                        )
                    )
                scan.metadata_ = {
                    **(scan.metadata_ or {}),
                    "adapter_result": result,
                    "normalized_findings": len(normalized_findings),
                }
                
                scan.status = "completed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
                
            except Exception as e:
                logger.error("scanner_failed", scanner=scanner_name, error=str(e))
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                await db.commit()
    
    asyncio.run(_execute())
