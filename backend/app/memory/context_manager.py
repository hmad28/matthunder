"""
Context Manager for Cross-Target Pattern Learning

Manages learning patterns across multiple targets and generates insights
based on historical data.
"""
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import json

from .persistence import MemoryPersistence


class ContextManager:
    """Manages cross-target pattern learning and context analysis"""

    def __init__(self, persistence: MemoryPersistence):
        """
        Initialize context manager

        Args:
            persistence: Memory persistence instance
        """
        self.persistence = persistence

    def extract_patterns(self, target_id: str) -> Dict[str, Any]:
        """
        Extract patterns from target context

        Args:
            target_id: Target domain or ID

        Returns:
            Dictionary with extracted patterns
        """
        entries = self.persistence.get_target_context(target_id)
        patterns = {
            "vulnerability_types": set(),
            "common_endpoints": set(),
            "technologies": set(),
            "port_patterns": defaultdict(int),
            "active_leads": [],
            "completed_checks": set(),
            "risk_assessment": {}
        }

        for entry in entries:
            content = entry.get("content", {})
            context_type = entry.get("context_type", "")

            if context_type == "vulnerability_journal":
                self._extract_journal_patterns(content, patterns)

            elif context_type == "reconnaissance_map":
                self._extract_recon_patterns(content, patterns)

            elif context_type == "target_metadata":
                self._extract_metadata_patterns(content, patterns)

        return patterns

    def _extract_journal_patterns(self, content: Dict[str, Any], patterns: Dict[str, Any]) -> None:
        """Extract patterns from vulnerability journal"""
        completed = content.get("completed_checks", [])
        active_leads = content.get("active_leads", [])

        patterns["completed_checks"].update(completed)

        for lead in active_leads:
            vuln_type = lead.get("potential_vuln", "")
            if vuln_type:
                patterns["vulnerability_types"].add(vuln_type)
            patterns["active_leads"].append(lead)

    def _extract_recon_patterns(self, content: Dict[str, Any], patterns: Dict[str, Any]) -> None:
        """Extract patterns from reconnaissance map"""
        live_hosts = content.get("live_hosts", [])

        for host in live_hosts:
            ports = host.get("ports", [])
            for port in ports:
                patterns["port_patterns"][port] += 1

            endpoints = content.get("untested_endpoints", [])
            for endpoint in endpoints:
                patterns["common_endpoints"].add(endpoint)

    def _extract_metadata_patterns(self, content: Dict[str, Any], patterns: Dict[str, Any]) -> None:
        """Extract patterns from target metadata"""
        scope_verification = content.get("scope_verification", "")
        if scope_verification:
            patterns["risk_assessment"]["scope_verified"] = scope_verification

        active_cve_checklist = content.get("active_cve_checklist", [])
        if active_cve_checklist:
            patterns["risk_assessment"]["cve_coverage"] = len(active_cve_checklist)

    def learn_cross_target(self, source_target: str, target_id: str) -> None:
        """
        Learn patterns from one target and apply to another

        Args:
            source_target: Source target domain or ID
            target_id: Target domain or ID to learn from
        """
        source_patterns = self.extract_patterns(source_target)
        target_patterns = self.extract_patterns(target_id)

        # Identify patterns to transfer
        learned_patterns = {
            "common_endpoints": source_patterns["common_endpoints"] & target_patterns["common_endpoints"],
            "technologies": source_patterns["technologies"] & target_patterns["technologies"],
            "port_patterns": {k: min(v, target_patterns["port_patterns"].get(k, 0))
                            for k, v in source_patterns["port_patterns"].items()
                            if k in target_patterns["port_patterns"]},
            "vulnerability_types": source_patterns["vulnerability_types"] & target_patterns["vulnerability_types"]
        }

        # Add learned patterns to target context
        self.persistence.add_context(
            target_id=target_id,
            scan_id="system",
            context_type="learning_patterns",
            content={
                "learned_from": source_target,
                "learned_at": datetime.utcnow().isoformat() + "Z",
                "patterns": learned_patterns
            },
            metadata={
                "type": "cross_target_learning",
                "source_target": source_target
            }
        )

    def get_target_insights(self, target_id: str) -> Dict[str, Any]:
        """
        Get comprehensive insights for a target

        Args:
            target_id: Target domain or ID

        Returns:
            Dictionary with target insights
        """
        patterns = self.extract_patterns(target_id)

        # Calculate risk scores
        risk_score = self._calculate_risk_score(patterns)

        # Get active leads with priority
        active_leads = self._prioritize_active_leads(patterns["active_leads"])

        return {
            "target_id": target_id,
            "patterns": patterns,
            "risk_assessment": {
                "risk_score": risk_score,
                "risk_level": self._get_risk_level(risk_score)
            },
            "active_leads": active_leads,
            "recommendations": self._generate_recommendations(patterns),
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }

    def _calculate_risk_score(self, patterns: Dict[str, Any]) -> float:
        """
        Calculate risk score based on patterns

        Args:
            patterns: Extracted patterns

        Returns:
            Risk score (0-1)
        """
        score = 0.0

        # Vulnerability types increase risk
        vuln_count = len(patterns["vulnerability_types"])
        score += min(vuln_count * 0.1, 0.4)

        # Active leads increase risk
        active_leads = len(patterns["active_leads"])
        score += min(active_leads * 0.05, 0.3)

        # Port patterns - many open ports increase risk
        open_ports = sum(1 for count in patterns["port_patterns"].values() if count > 1)
        score += min(open_ports * 0.02, 0.2)

        # Common endpoints suggest surface area
        endpoints_count = len(patterns["common_endpoints"])
        score += min(endpoints_count * 0.01, 0.1)

        return min(score, 1.0)

    def _get_risk_level(self, score: float) -> str:
        """Get risk level string from score"""
        if score >= 0.7:
            return "high"
        elif score >= 0.4:
            return "medium"
        else:
            return "low"

    def _prioritize_active_leads(self, active_leads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Prioritize active leads based on feromon-like scoring

        Args:
            active_leads: List of active leads

        Returns:
            Prioritized list of leads
        """
        for lead in active_leads:
            # Calculate lead priority score
            score = 0.0
            score += lead.get("pheromone_level", 0.5) * 0.6
            score += lead.get("confidence", 0.5) * 0.4
            lead["priority_score"] = score

        # Sort by priority score descending
        return sorted(active_leads, key=lambda x: x.get("priority_score", 0), reverse=True)

    def _generate_recommendations(self, patterns: Dict[str, Any]) -> List[str]:
        """
        Generate prioritized recommendations based on patterns

        Args:
            patterns: Extracted patterns

        Returns:
            List of recommendations
        """
        recommendations = []

        if patterns["vulnerability_types"]:
            vuln_types = ", ".join(list(patterns["vulnerability_types"])[:3])
            recommendations.append(f"Focus on: {vuln_types}")

        if patterns["active_leads"]:
            recommendations.append(f"Investigate {len(patterns['active_leads'])} active vulnerability leads")

        if patterns["port_patterns"]:
            high_risk_ports = [p for p, c in patterns["port_patterns"].items() if c > 2]
            if high_risk_ports:
                recommendations.append(f"Prioritize ports: {', '.join(map(str, high_risk_ports))}")

        if not patterns["completed_checks"]:
            recommendations.append("Start reconnaissance phase")

        return recommendations

    def get_session_summary(self, scan_id: str) -> Dict[str, Any]:
        """
        Get summary of a scanning session

        Args:
            scan_id: Scan session ID

        Returns:
            Session summary dictionary
        """
        entries = self.persistence.get_context_by_type("session_state")

        # Filter by scan_id
        session_entries = [e for e in entries if e.get("scan_id") == scan_id]

        if not session_entries:
            return {
                "scan_id": scan_id,
                "status": "not_found",
                "message": "Session state not found"
            }

        # Get most recent entry
        session_entry = session_entries[-1]
        content = session_entry.get("content", {})

        return {
            "scan_id": scan_id,
            "status": content.get("status", "unknown"),
            "current_phase": content.get("current_phase"),
            "progress": content.get("progress", 0),
            "findings_count": content.get("findings_count", 0),
            "active_leads": content.get("active_leads", []),
            "completed_tasks": content.get("completed_tasks", []),
            "last_updated": session_entry.get("timestamp")
        }

    def clear_old_context(self, days_old: int = 30) -> int:
        """
        Clear context older than specified days

        Args:
            days_old: Number of days to keep

        Returns:
            Number of entries cleared
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        cutoff_iso = cutoff_date.isoformat() + "Z"

        if not self.persistence.context_file.exists():
            return 0

        with self.persistence.lock:
            temp_file = self.persistence.context_file.with_suffix('.tmp')
            cleared_count = 0

            with self.persistence.context_file.open('r', encoding='utf-8') as src:
                with temp_file.open('w', encoding='utf-8') as dst:
                    header = self.persistence._get_context_header()
                    dst.write(header + '\n')

                    for line in src:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            timestamp = entry.get("timestamp")
                            if timestamp and timestamp < cutoff_iso:
                                cleared_count += 1
                                continue
                            dst.write(line + '\n')
                        except json.JSONDecodeError:
                            continue

            temp_file.replace(self.persistence.context_file)

        return cleared_count