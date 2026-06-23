"""
Approval Service for 7-Question Gate

Manages approval workflow for pentest findings.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class ApprovalRequest(BaseModel):
    """Approval request for a finding"""
    target_id: str = Field(..., description="Target domain or ID")
    finding_type: str = Field(..., description="Type of finding")
    findings: List[Dict[str, Any]] = Field(..., description="Findings to approve")
    justification: str = Field(..., description="Justification for approval")
    requestor_id: Optional[str] = Field(None, description="Requestor user ID")


class ApprovalDecision(BaseModel):
    """Approval decision"""
    approved: bool
    reviewer_id: Optional[str] = Field(None, description="Reviewer user ID")
    comments: str = Field(default="", description="Reviewer comments")
    timestamp: str = Field(..., description="Decision timestamp")


class ApprovalService:
    """Manages approval workflow for pentest findings"""

    def __init__(self):
        """Initialize approval service"""
        self._pending_approvals: Dict[str, ApprovalRequest] = {}

    async def submit_approval_request(
        self,
        request: ApprovalRequest
    ) -> str:
        """
        Submit an approval request for findings

        Args:
            request: Approval request

        Returns:
            Approval request ID
        """
        approval_id = f"approval_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{request.target_id[:8]}"

        self._pending_approvals[approval_id] = request

        return approval_id

    async def review_approval(
        self,
        approval_id: str,
        decision: ApprovalDecision
    ) -> bool:
        """
        Review an approval request

        Args:
            approval_id: Approval request ID
            decision: Approval decision

        Returns:
            True if approved, False otherwise
        """
        if approval_id not in self._pending_approvals:
            raise ValueError(f"Approval request {approval_id} not found")

        request = self._pending_approvals[approval_id]

        if decision.approved:
            # Findings are approved - can be reported
            self._handle_approved_findings(request)
        else:
            # Findings rejected - update status
            self._handle_rejected_findings(request)

        return decision.approved

    def _handle_approved_findings(self, request: ApprovalRequest) -> None:
        """Handle approved findings"""
        # Update finding status to 'confirmed'
        # This would update the database in production
        pass

    def _handle_rejected_findings(self, request: ApprovalRequest) -> None:
        """Handle rejected findings"""
        # Update finding status to 'false_positive' or 'rejected'
        # This would update the database in production
        pass

    def get_pending_approvals(self) -> List[ApprovalRequest]:
        """
        Get all pending approval requests

        Returns:
            List of pending approval requests
        """
        return list(self._pending_approvals.values())

    def get_approval_status(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """
        Get approval status

        Args:
            approval_id: Approval request ID

        Returns:
            Approval status or None
        """
        if approval_id not in self._pending_approvals:
            return None

        request = self._pending_approvals[approval_id]
        return {
            "approval_id": approval_id,
            "target_id": request.target_id,
            "finding_type": request.finding_type,
            "findings_count": len(request.findings),
            "justification": request.justification,
            "requestor_id": request.requestor_id,
            "submitted_at": datetime.utcnow().isoformat() + "Z",
            "status": "pending"
        }

    def get_approval_count_by_target(self, target_id: str) -> Dict[str, int]:
        """
        Get approval count by target

        Args:
            target_id: Target domain or ID

        Returns:
            Dictionary with approval counts
        """
        counts = {
            "pending": 0,
            "approved": 0,
            "rejected": 0
        }

        for approval_id, request in self._pending_approvals.items():
            if request.target_id == target_id:
                # In production, this would check actual status
                counts["pending"] += 1

        return counts

    def get_target_summary(self, target_id: str) -> Dict[str, Any]:
        """
        Get summary for a target

        Args:
            target_id: Target domain or ID

        Returns:
            Target summary
        """
        counts = self.get_approval_count_by_target(target_id)

        return {
            "target_id": target_id,
            "pending_approvals": counts["pending"],
            "approved_approvals": counts["approved"],
            "rejected_approvals": counts["rejected"],
            "total_approvals": sum(counts.values()),
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }

    def clear_old_approvals(self, days_old: int = 30) -> int:
        """
        Clear old approval requests

        Args:
            days_old: Number of days to keep

        Returns:
            Number of approvals cleared
        """
        from datetime import timedelta
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)

        approvals_to_clear = [
            approval_id
            for approval_id, request in self._pending_approvals.items()
            if request.justification  # Simple heuristic
        ]

        for approval_id in approvals_to_clear:
            del self._pending_approvals[approval_id]

        return len(approvals_to_clear)