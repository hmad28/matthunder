"""
Scanner Service - Business logic for scanner operations
"""
from uuid import UUID
from typing import Any
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models import ScannerRegistry, Scan, Finding, Target
from app.schemas import ScannerInfo, ScannerRunResponse
from app.core.exceptions import BadRequestException, ScannerNotFoundException, NotFoundException
from app.hunting.engine import TargetInput
from app.tasks.dispatch import celery_enabled
from app.core.logging import get_logger

logger = get_logger(__name__)


class ScannerService:
    """Service for scanner operations"""
    
    # Available scanners
    SCANNERS = {
        "blh": {
            "name": "blh",
            "display_name": "Broken Link Hunter",
            "description": "Check social/profile links (IG, Twitter, etc)",
            "category": "discovery"
        },
        "tpa": {
            "name": "tpa",
            "display_name": "3rd Party Assets",
            "description": "Find Drive/SharePoint/GitHub links on site",
            "category": "discovery"
        },
        "cred": {
            "name": "cred",
            "display_name": "Credential URLs",
            "description": "Search for leaked config/credential endpoints",
            "category": "discovery"
        },
        "ssti": {
            "name": "ssti",
            "display_name": "SSTI Probe",
            "description": "Test for Server-Side Template Injection",
            "category": "vuln"
        },
        "cors": {
            "name": "cors",
            "display_name": "CORS Misconfig",
            "description": "Check for CORS origin-reflection bugs",
            "category": "vuln"
        },
        "xss": {
            "name": "xss",
            "display_name": "XSS Scan",
            "description": "Reflected/DOM XSS detection (dalfox + manual)",
            "category": "vuln"
        },
        "sqli": {
            "name": "sqli",
            "display_name": "SQL Injection",
            "description": "Error-based SQLi probe + sqlmap wrapper",
            "category": "vuln"
        },
        "lfi": {
            "name": "lfi",
            "display_name": "LFI / Path Traversal",
            "description": "Local File Inclusion payload fuzzing",
            "category": "vuln"
        },
        "crlf": {
            "name": "crlf",
            "display_name": "CRLF Injection",
            "description": "Header injection via CRLF sequences",
            "category": "vuln"
        },
        "openredirect": {
            "name": "openredirect",
            "display_name": "Open Redirect",
            "description": "Redirect parameter fuzzing",
            "category": "vuln"
        },
        "ssrf": {
            "name": "ssrf",
            "display_name": "SSRF Probe",
            "description": "Server-Side Request Forgery (internal + OOB)",
            "category": "vuln"
        },
        "hostheader": {
            "name": "hostheader",
            "display_name": "Host Header Inject",
            "description": "Password reset poisoning + cache poisoning",
            "category": "vuln"
        },
        "graphql": {
            "name": "graphql",
            "display_name": "GraphQL Introspection",
            "description": "Schema leak + playground + weak auth",
            "category": "vuln"
        },
        "portscan": {
            "name": "portscan",
            "display_name": "Port Scan",
            "description": "Open port detection (naabu/nmap/socket)",
            "category": "infra"
        },
        "waf": {
            "name": "waf",
            "display_name": "WAF Detection",
            "description": "Identify Web Application Firewall",
            "category": "infra"
        },
        "jsanalysis": {
            "name": "jsanalysis",
            "display_name": "JS Analysis",
            "description": "Extract secrets/endpoints from JavaScript",
            "category": "infra"
        },
        "fuzzer": {
            "name": "fuzzer",
            "display_name": "Dir/Path Fuzzer",
            "description": "Content discovery (ffuf/feroxbuster/gobuster)",
            "category": "infra"
        },
        "tech": {
            "name": "tech",
            "display_name": "Tech Fingerprint",
            "description": "Detect stack + auto stack-specific hunting",
            "category": "infra"
        },
        "rank": {
            "name": "rank",
            "display_name": "Attack Surface Rank",
            "description": "Rank subdomains by attack value",
            "category": "infra"
        },
        "gf": {
            "name": "gf",
            "display_name": "GF Patterns",
            "description": "Filter URLs by vuln type",
            "category": "infra"
        },
    }
    
    @staticmethod
    async def get_available_scanners() -> list[ScannerInfo]:
        """Get list of available scanners"""
        scanners = []
        for name, info in ScannerService.SCANNERS.items():
            scanners.append(ScannerInfo(
                name=info["name"],
                display_name=info["display_name"],
                description=info["description"],
                category=info["category"],
                is_active=True
            ))
        return scanners
    
    @staticmethod
    async def run_scanner(
        scanner_name: str,
        target: str,
        config: dict[str, Any],
        user_id: UUID,
        db: AsyncSession
    ) -> ScannerRunResponse:
        """Run a specific scanner"""
        if scanner_name not in ScannerService.SCANNERS:
            raise ScannerNotFoundException(scanner_name)
        
        scanner_info = ScannerService.SCANNERS[scanner_name]
        try:
            normalized = TargetInput.normalize(target, scope=None)
        except ValueError as exc:
            raise BadRequestException(str(exc))
        normalized_target = normalized.domain

        result = await db.execute(
            select(Target).where(
                Target.domain == normalized_target,
                Target.created_by == user_id,
            )
        )
        target_record = result.scalar_one_or_none()
        if not target_record:
            target_record = Target(
                domain=normalized_target,
                scope=normalized.scope,
                created_by=user_id,
            )
            db.add(target_record)
            await db.commit()
            await db.refresh(target_record)
        
        # Create a scan record
        scan = Scan(
            target_id=target_record.id,
            scan_type=scanner_name,
            speed="standard",
            metadata_={"target": normalized_target, "config": config},
            created_by=user_id,
            status="pending"
        )
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        
        # Queue the scanner task. Local-native mode runs without Redis/Celery.
        if celery_enabled():
            from app.tasks.scan_tasks import run_scanner_task
            task = run_scanner_task.delay(str(scan.id), scanner_name, normalized_target, config)
            scan.celery_task_id = task.id
        else:
            from app.services.scan_service import ScanService
            asyncio.create_task(ScanService.execute_scan(str(scan.id)))
            scan.celery_task_id = None
        scan.status = "running"
        await db.commit()
        
        logger.info("scanner_started", scanner=scanner_name, target=normalized_target)
        
        return ScannerRunResponse(
            scan_id=scan.id,
            scanner=scanner_name,
            status="running",
            message=f"{scanner_info['display_name']} started on {normalized_target}"
        )
