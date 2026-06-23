"""
Async Context Updater for Celery Integration

Handles asynchronous context updates via Celery task queue
to avoid blocking scanning operations.
"""
from typing import Any, Dict, Optional
from datetime import datetime

from .persistence import MemoryPersistence


class AsyncContextUpdater:
    """Handles async context updates via Celery"""

    def __init__(self, persistence: MemoryPersistence):
        """
        Initialize async context updater

        Args:
            persistence: Memory persistence instance
        """
        self.persistence = persistence

    async def update_target_metadata(
        self,
        target_id: str,
        scan_id: str,
        host: str,
        scope_verification: str,
        active_cve_checklist: Optional[list[str]] = None
    ) -> None:
        """
        Update target metadata context

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            host: Target host
            scope_verification: Scope verification status
            active_cve_checklist: List of active CVEs
        """
        await self.persistence.add_context_async(
            target_id=target_id,
            scan_id=scan_id,
            context_type="target_metadata",
            content={
                "host": host,
                "scope_verification": scope_verification,
                "active_cve_checklist": active_cve_checklist or [],
                "updated_at": datetime.utcnow().isoformat() + "Z"
            },
            metadata={
                "type": "target_metadata_update",
                "scan_id": scan_id
            }
        )

    async def update_reconnaissance_map(
        self,
        target_id: str,
        scan_id: str,
        live_hosts: list[Dict[str, Any]],
        untested_endpoints: list[str]
    ) -> None:
        """
        Update reconnaissance map context

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            live_hosts: List of live hosts with port info
            untested_endpoints: List of untested endpoints
        """
        await self.persistence.add_context_async(
            target_id=target_id,
            scan_id=scan_id,
            context_type="reconnaissance_map",
            content={
                "live_hosts": live_hosts,
                "untested_endpoints": untested_endpoints,
                "updated_at": datetime.utcnow().isoformat() + "Z"
            },
            metadata={
                "type": "reconnaissance_update",
                "scan_id": scan_id
            }
        )

    async def add_vulnerability_lead(
        self,
        target_id: str,
        scan_id: str,
        endpoint: str,
        potential_vuln: str,
        confidence: float = 0.5,
        pheromone_level: float = 0.5
    ) -> None:
        """
        Add active vulnerability lead

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            endpoint: Vulnerable endpoint
            potential_vuln: Type of vulnerability
            confidence: Confidence score (0-1)
            pheromone_level: Pheromone level (0-1)
        """
        await self.persistence.add_context_async(
            target_id=target_id,
            scan_id=scan_id,
            context_type="vulnerability_journal",
            content={
                "endpoint": endpoint,
                "potential_vuln": potential_vuln,
                "confidence": confidence,
                "pheromone_level": pheromone_level,
                "status": "active",
                "discovered_at": datetime.utcnow().isoformat() + "Z"
            },
            metadata={
                "type": "vulnerability_lead",
                "scan_id": scan_id
            }
        )

    async def complete_check(
        self,
        target_id: str,
        scan_id: str,
        check_type: str,
        status: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Mark a check as completed

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            check_type: Type of check completed
            status: Status of check
            details: Optional details about the check
        """
        await self.persistence.add_context_async(
            target_id=target_id,
            scan_id=scan_id,
            context_type="vulnerability_journal",
            content={
                "check_type": check_type,
                "status": status,
                "details": details or {},
                "completed_at": datetime.utcnow().isoformat() + "Z"
            },
            metadata={
                "type": "check_completion",
                "scan_id": scan_id
            }
        )

    async def update_session_state(
        self,
        target_id: str,
        scan_id: str,
        status: str,
        current_phase: str,
        progress: float,
        findings_count: int = 0,
        active_leads: Optional[list[Dict[str, Any]]] = None
    ) -> None:
        """
        Update scanning session state

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            status: Current status
            current_phase: Current phase
            progress: Progress percentage (0-100)
            findings_count: Number of findings
            active_leads: Active vulnerability leads
        """
        await self.persistence.add_context_async(
            target_id=target_id,
            scan_id=scan_id,
            context_type="session_state",
            content={
                "status": status,
                "current_phase": current_phase,
                "progress": progress,
                "findings_count": findings_count,
                "active_leads": active_leads or [],
                "updated_at": datetime.utcnow().isoformat() + "Z"
            },
            metadata={
                "type": "session_state_update",
                "scan_id": scan_id
            }
        )

    async def save_finding(
        self,
        target_id: str,
        scan_id: str,
        finding: Dict[str, Any]
    ) -> None:
        """
        Save a finding to context

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            finding: Finding data
        """
        await self.persistence.add_context_async(
            target_id=target_id,
            scan_id=scan_id,
            context_type="vulnerability_journal",
            content={
                "finding": finding,
                "saved_at": datetime.utcnow().isoformat() + "Z"
            },
            metadata={
                "type": "finding_saved",
                "scan_id": scan_id
            }
        )

    async def learn_from_target(
        self,
        source_target: str,
        target_id: str
    ) -> None:
        """
        Learn patterns from one target and apply to another

        Args:
            source_target: Source target domain or ID
            target_id: Target domain or ID
        """
        await self.persistence.add_context_async(
            target_id=target_id,
            scan_id="system",
            context_type="learning_patterns",
            content={
                "learned_from": source_target,
                "learned_at": datetime.utcnow().isoformat() + "Z"
            },
            metadata={
                "type": "cross_target_learning",
                "source_target": source_target
            }
        )

    async def generate_daily_summary(
        self,
        target_id: str,
        scan_id: str,
        summary: Dict[str, Any]
    ) -> None:
        """
        Generate daily summary for target

        Args:
            target_id: Target domain or ID
            scan_id: Scan session ID
            summary: Summary data
        """
        await self.persistence.add_context_async(
            target_id=target_id,
            scan_id=scan_id,
            context_type="daily_summary",
            content={
                "summary": summary,
                "generated_at": datetime.utcnow().isoformat() + "Z"
            },
            metadata={
                "type": "daily_summary",
                "scan_id": scan_id
            }
        )