"""
Finding Enricher for AI Offensive AI

Enriches findings with additional data from various sources.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


class FindingEnricher:
    """Enriches findings with additional data"""

    def __init__(self):
        """Initialize finding enricher"""
        self._cvss_scoring = self._load_cvss_scoring()
        self._mitigation_database = self._load_mitigation_database()

    def _load_cvss_scoring(self) -> Dict[str, Dict[str, float]]:
        """Load CVSS scoring database"""
        # Simplified CVSS scoring
        return {
            "xss": {
                "base_score": 9.0,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "sqli": {
                "base_score": 10.0,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "lfi": {
                "base_score": 7.5,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "cors": {
                "base_score": 6.1,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
            },
            "ssrf": {
                "base_score": 7.5,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "sssti": {
                "base_score": 8.1,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "openredirect": {
                "base_score": 6.1,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
            },
            "hostheader": {
                "base_score": 7.5,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "crlf": {
                "base_score": 6.5,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            },
            "generic": {
                "base_score": 5.0,
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
            }
        }

    def _load_mitigation_database(self) -> Dict[str, List[str]]:
        """Load mitigation database"""
        return {
            "xss": [
                "Implement Content Security Policy (CSP)",
                "Use Input Validation and Output Encoding",
                "Implement HTTPOnly and Secure Cookies",
                "Use Sanitization Libraries",
                "Implement XSS Protection Frameworks"
            ],
            "sqli": [
                "Use Parameterized Queries (Prepared Statements)",
                "Use ORM with parameterized queries",
                "Implement Input Validation",
                "Use Stored Procedures",
                "Principle of Least Privilege"
            ],
            "lfi": [
                "Use Absolute Paths",
                "Implement Path Traversal Prevention",
                "Use File Access Controls",
                "Use Input Validation",
                "Use Web Server Configuration"
            ],
            "cors": [
                "Restrict Origin Headers",
                "Use Access-Control-Allow-Origin with Specific Origins",
                "Use Credentials Flag Properly",
                "Use HSTS Headers"
            ],
            "ssrf": [
                "Validate and Sanitize URLs",
                "Use Whitelisting",
                "Disable Proxy Allowlist",
                "Use CSP Headers"
            ],
            "sssti": [
                "Use Template Engine with Sandboxing",
                "Use Output Encoding",
                "Disable Template Engine Features",
                "Use CSP Headers"
            ],
            "openredirect": [
                "Validate Redirect URLs",
                "Use Whitelisting",
                "Implement URL Parameter Validation",
                "Use SameSite Cookie Flag"
            ],
            "hostheader": [
                "Validate Host Headers",
                "Use HSTS Headers",
                "Implement Host Header Validation",
                "Use HTTP Only Cookies"
            ],
            "crlf": [
                "Implement Input Validation",
                "Use HTTP Response Splitting Prevention",
                "Use Proper Encoding",
                "Use Web Server Configuration"
            ]
        }

    def enrich_finding(
        self,
        finding: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Enrich a finding with additional data

        Args:
            finding: Original finding
            context: Optional context

        Returns:
            Enriched finding
        """
        enriched = finding.copy()

        # Enrich with CVSS score
        cvss = self._enrich_cvss(enriched)
        enriched["cvss_score"] = cvss["base_score"]
        enriched["cvss_vector"] = cvss["vector"]

        # Enrich with remediation
        remediation = self._enrich_remediation(enriched)
        enriched["remediation"] = remediation

        # Enrich with context
        if context:
            enriched = self._enrich_with_context(enriched, context)

        enriched["enriched_at"] = datetime.utcnow().isoformat() + "Z"

        return enriched

    def _enrich_cvss(self, finding: Dict[str, Any]) -> Dict[str, float]:
        """Enrich with CVSS score"""
        vuln_type = finding.get("category", finding.get("scanner", "generic"))

        if vuln_type in self._cvss_scoring:
            return self._cvss_scoring[vuln_type]
        else:
            # Generic scoring
            return self._cvss_scoring["generic"]

    def _enrich_remediation(self, finding: Dict[str, Any]) -> str:
        """Enrich with remediation advice"""
        vuln_type = finding.get("category", finding.get("scanner", "generic"))

        if vuln_type in self._mitigation_database:
            mitigations = self._mitigation_database[vuln_type]
            return "\n".join(mitigations)

        return "Implement standard security best practices:\n- Use parameterized queries\n- Implement input validation\n- Use proper error handling\n- Keep software updated"

    def _enrich_with_context(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enrich finding with context"""
        enriched = finding.copy()

        # Add target metadata
        if "target_metadata" in context:
            target = context["target_metadata"]
            if "host" in target:
                enriched["target_host"] = target["host"]

        # Add reconnaissance context
        if "reconnaissance_map" in context:
            reconnaissance = context["reconnaissance_map"]
            if "live_hosts" in reconnaissance:
                enriched["discovered_endpoints"] = len(reconnaissance["live_hosts"])

        # Add vulnerability journal context
        if "vulnerability_journal" in context:
            journal = context["vulnerability_journal"]
            if "active_leads" in journal:
                enriched["potential_leads"] = len(journal["active_leads"])

        return enriched

    def generate_finding_summary(
        self,
        findings: List[Dict[str, Any]]
    ) -> str:
        """
        Generate summary for findings

        Args:
            findings: List of findings

        Returns:
            Summary string
        """
        summary_lines = [
            "# Finding Summary",
            f"Total Findings: {len(findings)}",
            "",
            "## Severity Distribution"
        ]

        # Calculate severity counts
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity, count in severity_counts.items():
            summary_lines.append(f"- {severity.upper()}: {count}")

        summary_lines.append("")
        summary_lines.append("## Top Vulnerabilities")

        # Get top 5 findings by severity
        top_findings = sorted(
            findings,
            key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4},
            reverse=True
        )[:5]

        for finding in top_findings:
            summary_lines.append(f"- {finding.get('title', 'Untitled')} ({finding.get('severity', 'unknown')})")
            if "url" in finding:
                summary_lines.append(f"  URL: {finding['url']}")

        summary_lines.append("")
        summary_lines.append("## Recommendations")

        summary_lines.append("- Prioritize critical and high-severity findings")
        summary_lines.append("- Verify scope and authorization")
        summary_lines.append("- Use automated testing for rapid triage")

        return '\n'.join(summary_lines)

    def calculate_risk_score(
        self,
        finding: Dict[str, Any]
    ) -> float:
        """
        Calculate risk score for a finding

        Args:
            finding: Finding data

        Returns:
            Risk score (0-1)
        """
        # Weighted score based on severity
        severity_weights = {
            "critical": 1.0,
            "high": 0.75,
            "medium": 0.5,
            "low": 0.25,
            "info": 0.1
        }

        base_score = severity_weights.get(finding.get("severity", "info"), 0.1)

        # Adjust based on context
        context = finding.get("context", {})
        context_score = 0.5  # Default context score

        if "target_host" in context:
            context_score = 0.75  # Target host detected
        elif "discovered_endpoints" in context:
            endpoints = context["discovered_endpoints"]
            context_score = min(1.0, 0.5 + (endpoints / 100))

        # Combine scores
        risk_score = (base_score + context_score) / 2

        return round(risk_score, 2)

    def generate_finding_report(
        self,
        target_id: str,
        findings: List[Dict[str, Any]],
        scan_id: str
    ) -> str:
        """
        Generate comprehensive finding report

        Args:
            target_id: Target domain or ID
            findings: List of findings
            scan_id: Scan session ID

        Returns:
            Report string
        """
        report_lines = [
            "# Matthunder Security Report",
            f"Target: {target_id}",
            f"Scan ID: {scan_id}",
            f"Generated: {datetime.utcnow().isoformat()}",
            "",
            "## Executive Summary"
        ]

        # Calculate statistics
        total_findings = len(findings)
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")
        low = sum(1 for f in findings if f.get("severity") == "low")

        report_lines.append(f"Total Findings: {total_findings}")
        report_lines.append(f"Critical: {critical}")
        report_lines.append(f"High: {high}")
        report_lines.append(f"Medium: {medium}")
        report_lines.append(f"Low: {low}")

        report_lines.append("")
        report_lines.append("## Detailed Findings")

        for finding in findings:
            report_lines.append(f"\n### {finding.get('title', 'Untitled')}")
            report_lines.append(f"Severity: {finding.get('severity', 'unknown')}")
            report_lines.append(f"Type: {finding.get('category', finding.get('scanner', 'unknown'))}")
            if "url" in finding:
                report_lines.append(f"URL: {finding['url']}")
            if "cvss_score" in finding:
                report_lines.append(f"CVSS Score: {finding['cvss_score']}")
            if "description" in finding:
                report_lines.append(f"Description: {finding['description']}")

        report_lines.append("")
        report_lines.append("## Remediation")

        report_lines.append("Prioritize critical and high-severity findings:")
        report_lines.append("1. Implement immediate security patches")
        report_lines.append("2. Conduct thorough testing in controlled environment")
        report_lines.append("3. Coordinate with development team")
        report_lines.append("4. Document all remediation steps")

        return '\n'.join(report_lines)

    def enrich_batch(
        self,
        findings: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Enrich multiple findings

        Args:
            findings: List of findings
            context: Optional context

        Returns:
            Enriched findings list
        """
        enriched_findings = []

        for finding in findings:
            enriched = self.enrich_finding(finding, context)
            enriched_findings.append(enriched)

        return enriched_findings

    def calculate_risk_matrix(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate risk matrix for findings

        Args:
            findings: List of findings

        Returns:
            Risk matrix
        """
        risk_matrix = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "risk_score": 0.0,
            "risk_level": "low"
        }

        for finding in findings:
            severity = finding.get("severity", "info")
            risk_matrix[severity] += 1

        # Calculate overall risk score
        risk_matrix["risk_score"] = self.calculate_risk_score({
            "severity": "critical"
        })

        # Determine overall risk level
        critical_count = risk_matrix["critical"]
        high_count = risk_matrix["high"]

        if critical_count > 0:
            risk_matrix["risk_level"] = "critical"
        elif high_count > 5:
            risk_matrix["risk_level"] = "high"
        elif high_count > 0:
            risk_matrix["risk_level"] = "medium"
        else:
            risk_matrix["risk_level"] = "low"

        return risk_matrix