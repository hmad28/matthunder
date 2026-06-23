"""
Context Reducer for AI Offensive AI

Reduces context for AI consumption by filtering and summarizing.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


class ContextReducer:
    """Reduces context for AI consumption"""

    def __init__(self):
        """Initialize context reducer"""
        self._important_keywords = [
            "vulnerability",
            "exploit",
            "injection",
            "attack",
            "injection",
            "payload",
            "payloads",
            "exploitation",
            "exfiltration",
            "credentials"
        ]

    def reduce_for_ai(
        self,
        findings: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Reduce context for AI consumption

        Args:
            findings: List of findings
            context: Optional context

        Returns:
            Reduced context string
        """
        context_lines = []

        # Add findings summary
        context_lines.append("# AI-Ready Context Summary")
        context_lines.append(f"Total Findings: {len(findings)}")

        # Add critical findings
        critical_findings = [
            f for finding in findings
            if finding.get("severity") in ["critical", "high"]
        ]
        context_lines.append(f"\n# Critical Findings: {len(critical_findings)}")

        for finding in critical_findings:
            if "url" in finding:
                context_lines.append(f"\n**URL**: {finding['url']}")
            if "title" in finding:
                context_lines.append(f"**Title**: {finding['title']}")
            if "description" in finding:
                desc = finding['description']
                if len(desc) > 200:
                    desc = desc[:200] + "..."
                context_lines.append(f"**Description**: {desc}")
            if "severity" in finding:
                context_lines.append(f"**Severity**: {finding['severity']}")

        # Add context if available
        if context:
            context_lines.append(f"\n# Additional Context")

            if "target_metadata" in context:
                target = context["target_metadata"]
                if "host" in target:
                    context_lines.append(f"**Target**: {target['host']}")
                if "scope_verification" in target:
                    context_lines.append(f"**Scope Verified**: {target['scope_verification']}")

            if "reconnaissance_map" in context:
                reconnaissance = context["reconnaissance_map"]
                if "live_hosts" in reconnaissance:
                    hosts = reconnaissance["live_hosts"]
                    context_lines.append(f"**Live Hosts**: {len(hosts)} hosts found")

            if "vulnerability_journal" in context:
                journal = context["vulnerability_journal"]
                if "active_leads" in journal:
                    leads = journal["active_leads"]
                    context_lines.append(f"**Active Leads**: {len(leads)} potential vulnerabilities")

        context = '\n'.join(context_lines)

        return context

    def extract_key_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Extract key findings for AI analysis

        Args:
            findings: List of findings

        Returns:
            Key findings list
        """
        key_findings = []

        for finding in findings:
            if finding.get("severity") in ["critical", "high"]:
                key_findings.append(finding)

        return key_findings

    def generate_attack_summary(
        self,
        target_id: str,
        findings: List[Dict[str, Any]]
    ) -> str:
        """
        Generate attack summary for AI

        Args:
            target_id: Target domain or ID
            findings: List of findings

        Returns:
            Attack summary string
        """
        summary_lines = [
            "# Attack Summary",
            f"Target: {target_id}",
            f"Total Findings: {len(findings)}",
            "",
            "## Critical Vulnerabilities"
        ]

        critical = [f for f in findings if f.get("severity") in ["critical", "high"]]
        for finding in critical:
            summary_lines.append(f"- {finding.get('title', 'Untitled')} ({finding.get('severity', 'unknown')})")
            if "url" in finding:
                summary_lines.append(f"  URL: {finding['url']}")

        summary_lines.append("")
        summary_lines.append("## Potential Attack Vectors")

        # Analyze findings by category
        categories = self._categorize_by_category(findings)
        for category, category_findings in categories.items():
            if category_findings:
                summary_lines.append(f"- {category}: {len(category_findings)}")

        summary_lines.append("")
        summary_lines.append("## Recommendations")

        summary_lines.append("- Prioritize critical vulnerabilities")
        summary_lines.append("- Consider automated exploitation for high-severity issues")
        summary_lines.append("- Verify scope and authorization before exploitation")

        return '\n'.join(summary_lines)

    def _categorize_by_category(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Categorize findings by category"""
        categories = {
            "SQL Injection": [],
            "Cross-Site Scripting": [],
            "Server-Side Request Forgery": [],
            "Local File Inclusion": [],
            "Cross-Origin Resource Sharing": [],
            "Server-Side Template Injection": [],
            "Open Redirect": [],
            "HTTP Header Injection": [],
            "Other": []
        }

        for finding in findings:
            category = finding.get("category", "Other")
            if category in categories:
                categories[category].append(finding)

        return categories

    def create_context_window(
        self,
        current_context: str,
        new_findings: List[Dict[str, Any]],
        window_size: int = 5
    ) -> str:
        """
        Create context window for AI

        Args:
            current_context: Current context
            new_findings: New findings to add
            window_size: Number of recent findings to include

        Returns:
            Context window string
        """
        context_lines = []

        # Add previous context
        context_lines.append("# Previous Context")
        context_lines.append(current_context)

        # Add new findings
        context_lines.append("\n# Recent Findings")

        recent_findings = new_findings[-window_size:]
        for finding in recent_findings:
            context_lines.append(f"\n**Finding**: {finding.get('title', 'Untitled')}")
            if "url" in finding:
                context_lines.append(f"**URL**: {finding['url']}")
            if "description" in finding:
                context_lines.append(f"**Description**: {finding['description']}")

        return '\n'.join(context_lines)

    def extract_threat_indicators(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """
        Extract threat indicators from findings

        Args:
            findings: List of findings

        Returns:
            List of threat indicators
        """
        indicators = []

        for finding in findings:
            # Extract URLs
            if "url" in finding:
                indicators.append(f"URL: {finding['url']}")

            # Extract potential attack vectors
            if "title" in finding:
                title = finding['title'].lower()
                if any(word in title for word in self._important_keywords):
                    indicators.append(f"Potential Attack: {finding['title']}")

        return indicators

    def normalize_severity(
        self,
        severity: str
    ) -> str:
        """
        Normalize severity string

        Args:
            severity: Severity string

        Returns:
            Normalized severity
        """
        severity_map = {
            "CRITICAL": "critical",
            "critical": "critical",
            "HIGH": "high",
            "high": "high",
            "MEDIUM": "medium",
            "medium": "medium",
            "LOW": "low",
            "low": "low",
            "INFO": "info",
            "info": "info"
        }

        return severity_map.get(severity.upper(), severity)

    def filter_by_severity(
        self,
        findings: List[Dict[str, Any]],
        min_severity: str
    ) -> List[Dict[str, Any]]:
        """
        Filter findings by severity

        Args:
            findings: List of findings
            min_severity: Minimum severity (low, medium, high, critical)

        Returns:
            Filtered findings
        """
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        min_order = severity_order.get(min_severity, 0)

        return [
            finding for finding in findings
            if severity_order.get(finding.get("severity", "low"), 0) >= min_order
        ]