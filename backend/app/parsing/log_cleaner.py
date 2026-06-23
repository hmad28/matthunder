"""
Log Cleaner for AI Offensive AI

Cleans and normalizes raw scanner output for AI consumption.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime


class LogCleaner:
    """Cleans and normalizes scanner log output"""

    def __init__(self):
        """Initialize log cleaner"""
        self._noise_patterns = self._load_noise_patterns()

    def _load_noise_patterns(self) -> Dict[str, List[str]]:
        """Load patterns to filter out as noise"""
        return {
            "debug": [
                "DEBUG",
                "debug",
                "[DEBUG]",
                "verbose"
            ],
            "info": [
                "INFO",
                "info",
                "[INFO]",
                "verbose"
            ],
            "warnings": [
                "WARNING",
                "warning",
                "WARN",
                "warn",
                "[WARN]"
            ],
            "errors": [
                "ERROR",
                "error",
                "[ERROR]",
                "fatal",
                "FATAL"
            ],
            "progress": [
                "progress",
                "Progress",
                "scanning",
                "Scanning",
                "checking",
                "Checking"
            ],
            "connection": [
                "connection",
                "Connection",
                "established",
                "Established"
            ]
        }

    def clean_log(self, raw_log: str) -> str:
        """
        Clean raw log output

        Args:
            raw_log: Raw log output

        Returns:
            Cleaned log output
        """
        if not raw_log:
            return ""

        # Normalize line endings
        lines = raw_log.replace('\r\n', '\n').split('\n')

        # Filter out noise
        cleaned_lines = self._filter_noise(lines)

        # Remove duplicates while preserving order
        cleaned_lines = self._remove_duplicates(cleaned_lines)

        return '\n'.join(cleaned_lines)

    def _filter_noise(self, lines: List[str]) -> List[str]:
        """
        Filter out noise patterns

        Args:
            lines: List of log lines

        Returns:
            Filtered lines
        """
        filtered = []

        for line in lines:
            line_lower = line.lower()

            # Check if line contains noise
            is_noise = False
            for category, patterns in self._noise_patterns.items():
                if any(pattern.lower() in line_lower for pattern in patterns):
                    is_noise = True
                    break

            if not is_noise:
                filtered.append(line)

        return filtered

    def _remove_duplicates(self, lines: List[str]) -> List[str]:
        """
        Remove duplicate lines while preserving order

        Args:
            lines: List of lines

        Returns:
            Lines without duplicates
        """
        seen = set()
        unique_lines = []

        for line in lines:
            if line not in seen:
                seen.add(line)
                unique_lines.append(line)

        return unique_lines

    def extract_findings(self, raw_log: str) -> List[Dict[str, Any]]:
        """
        Extract findings from raw log

        Args:
            raw_log: Raw log output

        Returns:
            List of extracted findings
        """
        findings = []

        # Clean the log first
        cleaned_log = self.clean_log(raw_log)

        # Try to parse as structured format
        structured_findings = self._parse_structured_format(cleaned_log)
        if structured_findings:
            findings.extend(structured_findings)

        # Try to parse as JSON
        json_findings = self._parse_json_format(cleaned_log)
        if json_findings:
            findings.extend(json_findings)

        # Try to parse as key-value pairs
        kv_findings = self._parse_key_value_format(cleaned_log)
        if kv_findings:
            findings.extend(kv_findings)

        return findings

    def _parse_structured_format(self, log: str) -> List[Dict[str, Any]]:
        """
        Parse structured log format

        Args:
            log: Cleaned log

        Returns:
            List of findings
        """
        findings = []
        lines = log.split('\n')

        for line in lines:
            # Look for structured patterns
            if ':' in line and len(line) < 500:
                try:
                    key, value = line.split(':', 1)
                    findings.append({
                        "type": "structured",
                        "key": key.strip(),
                        "value": value.strip(),
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    })
                except ValueError:
                    continue

        return findings

    def _parse_json_format(self, log: str) -> List[Dict[str, Any]]:
        """
        Parse JSON log format

        Args:
            log: Cleaned log

        Returns:
            List of findings
        """
        import json

        findings = []

        # Try to parse as JSON
        try:
            data = json.loads(log)
            if isinstance(data, list):
                findings.extend(data)
            elif isinstance(data, dict):
                findings.append(data)
        except json.JSONDecodeError:
            pass

        return findings

    def _parse_key_value_format(self, log: str) -> List[Dict[str, Any]]:
        """
        Parse key-value format

        Args:
            log: Cleaned log

        Returns:
            List of findings
        """
        findings = []
        lines = log.split('\n')

        for line in lines:
            if ':' in line and len(line) < 500:
                try:
                    key, value = line.split(':', 1)
                    findings.append({
                        "type": "kv",
                        "key": key.strip(),
                        "value": value.strip(),
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    })
                except ValueError:
                    continue

        return findings

    def categorize_findings(
        self,
        findings: List[Dict[str, Any]],
        log_type: str
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorize findings by type

        Args:
            findings: List of findings
            log_type: Type of log (nuclei, sqlmap, etc.)

        Returns:
            Dictionary with categorized findings
        """
        categories = {
            "vulnerabilities": [],
            "endpoints": [],
            "errors": [],
            "warnings": [],
            "info": [],
            "other": []
        }

        for finding in findings:
            if log_type == "nuclei":
                self._categorize_nuclei(finding, categories)
            elif log_type == "sqlmap":
                self._categorize_sqlmap(finding, categories)
            elif log_type == "httpx":
                self._categorize_httpx(finding, categories)
            else:
                self._categorize_generic(finding, categories)

        return categories

    def _categorize_nuclei(self, finding: Dict[str, Any], categories: Dict[str, List[Dict[str, Any]]]) -> None:
        """Categorize Nuclei findings"""
        severity = finding.get("severity", "info")

        if severity in ["critical", "high", "medium"]:
            categories["vulnerabilities"].append(finding)
        else:
            categories["info"].append(finding)

    def _categorize_sqlmap(self, finding: Dict[str, Any], categories: Dict[str, List[Dict[str, Any]]]) -> None:
        """Categorize SQLMap findings"""
        status = finding.get("status", "")

        if "succe" in status.lower() or "injection" in status.lower():
            categories["vulnerabilities"].append(finding)
        elif "error" in status.lower():
            categories["errors"].append(finding)
        else:
            categories["info"].append(finding)

    def _categorize_httpx(self, finding: Dict[str, Any], categories: Dict[str, List[Dict[str, Any]]]) -> None:
        """Categorize Httpx findings"""
        if "status" in finding:
            status_code = finding["status"]
            if status_code >= 400:
                categories["errors"].append(finding)
            else:
                categories["endpoints"].append(finding)
        else:
            categories["info"].append(finding)

    def _categorize_generic(self, finding: Dict[str, Any], categories: Dict[str, List[Dict[str, Any]]]) -> None:
        """Categorize generic findings"""
        if "vulnerability" in finding.get("type", "").lower():
            categories["vulnerabilities"].append(finding)
        elif "error" in finding.get("type", "").lower():
            categories["errors"].append(finding)
        elif "warning" in finding.get("type", "").lower():
            categories["warnings"].append(finding)
        else:
            categories["other"].append(finding)

    def reduce_context(
        self,
        findings: List[Dict[str, Any]],
        max_tokens: int = 4000
    ) -> str:
        """
        Reduce context for AI consumption

        Args:
            findings: List of findings
            max_tokens: Maximum tokens for context

        Returns:
            Reduced context string
        """
        # Filter critical findings
        critical_findings = [
            f for finding in findings
            if finding.get("severity") in ["critical", "high"]
        ]

        # Build context from critical findings
        context_lines = []
        context_lines.append(f"# Critical Findings ({len(critical_findings)})")

        for finding in critical_findings:
            if "url" in finding:
                context_lines.append(f"URL: {finding['url']}")
            if "title" in finding:
                context_lines.append(f"Title: {finding['title']}")
            if "description" in finding:
                context_lines.append(f"Description: {finding['description']}")
            if "severity" in finding:
                context_lines.append(f"Severity: {finding['severity']}")

        context_lines.append(f"\n# Total Findings: {len(findings)}")

        context = '\n'.join(context_lines)

        # Truncate if needed
        if len(context) > max_tokens:
            context = context[:max_tokens] + "..."

        return context

    def get_log_statistics(self, raw_log: str) -> Dict[str, Any]:
        """
        Get statistics from log

        Args:
            raw_log: Raw log output

        Returns:
            Statistics dictionary
        """
        cleaned_log = self.clean_log(raw_log)
        lines = cleaned_log.split('\n')

        stats = {
            "total_lines": len(lines),
            "total_findings": 0,
            "vulnerability_count": 0,
            "error_count": 0,
            "warning_count": 0,
            "info_count": 0,
            "unique_urls": set()
        }

        # Extract findings and statistics
        findings = self.extract_findings(cleaned_log)
        stats["total_findings"] = len(findings)

        for finding in findings:
            if "vulnerability" in finding.get("type", "").lower():
                stats["vulnerability_count"] += 1
            if "error" in finding.get("type", "").lower():
                stats["error_count"] += 1
            if "warning" in finding.get("type", "").lower():
                stats["warning_count"] += 1
            if "info" in finding.get("type", "").lower():
                stats["info_count"] += 1

            if "url" in finding:
                stats["unique_urls"].add(finding["url"])

        stats["unique_urls"] = list(stats["unique_urls"])

        return stats