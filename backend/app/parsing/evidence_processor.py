"""
Evidence Processor for AI Offensive AI

Processes and classifies evidence from scanner output.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


class EvidenceProcessor:
    """Processes and classifies evidence"""

    def __init__(self):
        """Initialize evidence processor"""
        self._evidence_types = {
            "http_response": [
                "status_code",
                "response_body",
                "headers",
                "response_time"
            ],
            "payload": [
                "payload",
                "payloads",
                "exploit",
                "exploitation",
                "command"
            ],
            "screenshot": [
                "screenshot",
                "screenshot_data",
                "image",
                "capture"
            ],
            "log": [
                "log",
                "logs",
                "output",
                "stdout",
                "stderr"
            ],
            "metadata": [
                "metadata",
                "scan_metadata",
                "tool_version"
            ]
        }

    def process_evidence(
        self,
        raw_evidence: str,
        evidence_type: str
    ) -> Dict[str, Any]:
        """
        Process raw evidence

        Args:
            raw_evidence: Raw evidence string
            evidence_type: Type of evidence

        Returns:
            Processed evidence
        """
        evidence = {
            "type": evidence_type,
            "processed_at": datetime.utcnow().isoformat() + "Z",
            "content": raw_evidence,
            "size": len(raw_evidence.encode('utf-8')),
            "processed": True
        }

        # Process based on type
        if evidence_type == "http_response":
            evidence = self._process_http_response(raw_evidence, evidence)
        elif evidence_type == "payload":
            evidence = self._process_payload(raw_evidence, evidence)
        elif evidence_type == "log":
            evidence = self._process_log(raw_evidence, evidence)
        elif evidence_type == "screenshot":
            evidence = self._process_screenshot(raw_evidence, evidence)
        elif evidence_type == "metadata":
            evidence = self._process_metadata(raw_evidence, evidence)

        return evidence

    def _process_http_response(self, raw_evidence: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Process HTTP response evidence"""
        lines = raw_evidence.split('\n')

        # Extract status code
        for line in lines:
            if 'status' in line.lower() and ':' in line:
                try:
                    status_part = line.split(':', 1)[0]
                    evidence["status_code"] = status_part.strip()
                except ValueError:
                    continue

        # Extract headers
        headers = {}
        current_header = None
        for line in lines:
            if ':' in line:
                header, value = line.split(':', 1)
                current_header = header.strip()
                headers[current_header] = value.strip()
            elif current_header:
                headers[current_header] += '\n' + line.strip()

        if headers:
            evidence["headers"] = headers

        return evidence

    def _process_payload(self, raw_evidence: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Process payload evidence"""
        evidence["payload_type"] = "unknown"
        evidence["payload_size"] = len(raw_evidence)

        # Detect payload type
        if "sql" in raw_evidence.lower():
            evidence["payload_type"] = "sql_injection"
        elif "xss" in raw_evidence.lower():
            evidence["payload_type"] = "cross_site_scripting"
        elif "rce" in raw_evidence.lower() or "command" in raw_evidence.lower():
            evidence["payload_type"] = "remote_code_execution"

        return evidence

    def _process_log(self, raw_evidence: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Process log evidence"""
        lines = raw_evidence.split('\n')

        # Count errors and warnings
        errors = sum(1 for line in lines if 'error' in line.lower())
        warnings = sum(1 for line in lines if 'warning' in line.lower())

        evidence["errors"] = errors
        evidence["warnings"] = warnings
        evidence["line_count"] = len(lines)

        return evidence

    def _process_screenshot(self, raw_evidence: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Process screenshot evidence"""
        evidence["format"] = "unknown"
        evidence["dimensions"] = None

        # Simple detection
        if "data:image" in raw_evidence.lower():
            evidence["format"] = "base64_image"
            evidence["size_mb"] = len(raw_evidence) / (1024 * 1024)
        elif "png" in raw_evidence.lower() or "jpg" in raw_evidence.lower():
            evidence["format"] = "image"
            evidence["size_kb"] = len(raw_evidence) / 1024

        return evidence

    def _process_metadata(self, raw_evidence: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Process metadata evidence"""
        try:
            import json
            metadata = json.loads(raw_evidence)
            evidence["metadata"] = metadata
        except json.JSONDecodeError:
            evidence["metadata"] = {}

        return evidence

    def classify_evidence(
        self,
        evidence: Dict[str, Any]
    ) -> str:
        """
        Classify evidence type

        Args:
            evidence: Processed evidence

        Returns:
            Evidence type
        """
        if "status_code" in evidence or "headers" in evidence:
            return "http_response"
        elif "payload" in evidence or "payload_type" in evidence:
            return "payload"
        elif "errors" in evidence or "warnings" in evidence:
            return "log"
        elif "format" in evidence:
            return "screenshot"
        elif "metadata" in evidence:
            return "metadata"

        # Default classification
        return "other"

    def extract_evidence_summary(
        self,
        evidence: Dict[str, Any]
    ) -> str:
        """
        Extract evidence summary

        Args:
            evidence: Processed evidence

        Returns:
            Summary string
        """
        summary_lines = []

        summary_lines.append(f"# Evidence Summary")
        summary_lines.append(f"Type: {evidence.get('type', 'unknown')}")
        summary_lines.append(f"Processed: {evidence.get('processed', False)}")
        summary_lines.append(f"Size: {evidence.get('size', 0)} bytes")

        if "status_code" in evidence:
            summary_lines.append(f"Status Code: {evidence['status_code']}")

        if "payload_type" in evidence:
            summary_lines.append(f"Payload Type: {evidence['payload_type']}")

        if "errors" in evidence:
            summary_lines.append(f"Errors: {evidence['errors']}")

        if "warnings" in evidence:
            summary_lines.append(f"Warnings: {evidence['warnings']}")

        return '\n'.join(summary_lines)

    def create_evidence_package(
        self,
        findings: List[Dict[str, Any]],
        evidence: Dict[str, Any]
    ) -> str:
        """
        Create evidence package for AI analysis

        Args:
            findings: List of findings
            evidence: Processed evidence

        Returns:
            Evidence package string
        """
        package_lines = []

        # Add findings context
        package_lines.append("# Evidence Package for AI Analysis")
        package_lines.append(f"\n# Findings ({len(findings)})")

        for finding in findings:
            package_lines.append(f"\n**Finding**: {finding.get('title', 'Untitled')}")
            if "url" in finding:
                package_lines.append(f"**URL**: {finding['url']}")
            if "severity" in finding:
                package_lines.append(f"**Severity**: {finding['severity']}")

        # Add evidence
        package_lines.append(f"\n# Evidence ({evidence.get('type', 'unknown')})")
        package_lines.append(self.extract_evidence_summary(evidence))

        return '\n'.join(package_lines)

    def normalize_evidence_format(
        self,
        evidence: Dict[str, Any]
    ) -> str:
        """
        Normalize evidence format

        Args:
            evidence: Processed evidence

        Returns:
            Normalized format string
        """
        if evidence.get("type") == "http_response":
            return "http_response"
        elif evidence.get("type") == "payload":
            return "payload"
        elif evidence.get("type") == "log":
            return "log"
        elif evidence.get("type") == "screenshot":
            return "screenshot"
        else:
            return "text"

    def filter_sensitive_data(
        self,
        evidence: str,
        sensitive_patterns: Optional[List[str]] = None
    ) -> str:
        """
        Filter sensitive data from evidence

        Args:
            evidence: Evidence string
            sensitive_patterns: Patterns to filter

        Returns:
            Evidence with sensitive data removed
        """
        if sensitive_patterns is None:
            sensitive_patterns = [
                "password",
                "api_key",
                "token",
                "secret",
                "credential",
                "token",
                "session",
                "cookie"
            ]

        evidence_lines = evidence.split('\n')
        filtered_lines = []

        for line in evidence_lines:
            is_sensitive = False
            for pattern in sensitive_patterns:
                if pattern.lower() in line.lower():
                    is_sensitive = True
                    break

            if not is_sensitive:
                filtered_lines.append(line)

        return '\n'.join(filtered_lines)